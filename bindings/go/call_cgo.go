//go:build !windows

package rustleaks

/*
#include <stddef.h>
#include <stdint.h>

uint64_t spike_add(uint64_t a, uint64_t b);
uint64_t spike_sum(const uint8_t *ptr, size_t len);
uint64_t spike_stack(uint32_t kib);
*/
import "C"

import "unsafe"

// loadLibrary does nothing on Linux and macOS: cgo links the static library
// into the program.
func loadLibrary(string) error {
	return nil
}

func spikeAdd(a, b uint64) uint64 {
	return uint64(C.spike_add(C.uint64_t(a), C.uint64_t(b)))
}

func spikeSum(data []byte) uint64 {
	if len(data) == 0 {
		return uint64(C.spike_sum(nil, 0))
	}
	return uint64(C.spike_sum((*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data))))
}

func spikeStack(kib uint32) uint64 {
	return uint64(C.spike_stack(C.uint32_t(kib)))
}
