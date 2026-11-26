//go:build cgo && !windows

package rustleaks

/*
#include "rustleaks.h"
*/
import "C"

import "unsafe"

// On Linux and macOS cgo links the Rust static library into the program, so
// there is nothing to load.
func loadNativeLibrary() error { return nil }

// libraryPathUsed reports whether SetLibraryPath and RUSTLEAKS_LIBRARY_PATH
// choose the library on this system.
const libraryPathUsed = false

// The Go mirrors in abi.go must have the C sizes and field offsets. Each
// pair of constants below fails to compile when a value differs, because a
// negative uintptr constant overflows.
const (
	_ = unsafe.Sizeof(nativeBytes{}) - unsafe.Sizeof(C.rustleaks_bytes{})
	_ = unsafe.Sizeof(C.rustleaks_bytes{}) - unsafe.Sizeof(nativeBytes{})

	_ = unsafe.Sizeof(scanArgs{}) - unsafe.Sizeof(C.rustleaks_scan_args{})
	_ = unsafe.Sizeof(C.rustleaks_scan_args{}) - unsafe.Sizeof(scanArgs{})
	_ = unsafe.Offsetof(scanArgs{}.overrides) - unsafe.Offsetof(C.rustleaks_scan_args{}.overrides)
	_ = unsafe.Offsetof(C.rustleaks_scan_args{}.overrides) - unsafe.Offsetof(scanArgs{}.overrides)
	_ = unsafe.Offsetof(scanArgs{}.deadlineNS) - unsafe.Offsetof(C.rustleaks_scan_args{}.deadline_ns)
	_ = unsafe.Offsetof(C.rustleaks_scan_args{}.deadline_ns) - unsafe.Offsetof(scanArgs{}.deadlineNS)
	_ = unsafe.Offsetof(scanArgs{}.allowComments) - unsafe.Offsetof(C.rustleaks_scan_args{}.allow_comments)
	_ = unsafe.Offsetof(C.rustleaks_scan_args{}.allow_comments) - unsafe.Offsetof(scanArgs{}.allowComments)

	_ = unsafe.Sizeof(ruleView{}) - unsafe.Sizeof(C.rustleaks_rule_view{})
	_ = unsafe.Sizeof(C.rustleaks_rule_view{}) - unsafe.Sizeof(ruleView{})
	_ = unsafe.Offsetof(ruleView{}.keywordCount) - unsafe.Offsetof(C.rustleaks_rule_view{}.keyword_count)
	_ = unsafe.Offsetof(C.rustleaks_rule_view{}.keyword_count) - unsafe.Offsetof(ruleView{}.keywordCount)

	_ = unsafe.Sizeof(findingView{}) - unsafe.Sizeof(C.rustleaks_finding_view{})
	_ = unsafe.Sizeof(C.rustleaks_finding_view{}) - unsafe.Sizeof(findingView{})
	_ = unsafe.Offsetof(findingView{}.path) - unsafe.Offsetof(C.rustleaks_finding_view{}.path)
	_ = unsafe.Offsetof(C.rustleaks_finding_view{}.path) - unsafe.Offsetof(findingView{}.path)
	_ = unsafe.Offsetof(findingView{}.matchEnd) - unsafe.Offsetof(C.rustleaks_finding_view{}.match_end)
	_ = unsafe.Offsetof(C.rustleaks_finding_view{}.match_end) - unsafe.Offsetof(findingView{}.matchEnd)
	_ = unsafe.Offsetof(findingView{}.entropy) - unsafe.Offsetof(C.rustleaks_finding_view{}.entropy)
	_ = unsafe.Offsetof(C.rustleaks_finding_view{}.entropy) - unsafe.Offsetof(findingView{}.entropy)
	_ = unsafe.Offsetof(findingView{}.matchRangeExact) - unsafe.Offsetof(C.rustleaks_finding_view{}.match_range_exact)
	_ = unsafe.Offsetof(C.rustleaks_finding_view{}.match_range_exact) - unsafe.Offsetof(findingView{}.matchRangeExact)

	_ = unsafe.Sizeof(statusView{}) - unsafe.Sizeof(C.rustleaks_status_view{})
	_ = unsafe.Sizeof(C.rustleaks_status_view{}) - unsafe.Sizeof(statusView{})
	_ = unsafe.Offsetof(statusView{}.normalizationBytes) - unsafe.Offsetof(C.rustleaks_status_view{}.normalization_bytes)
	_ = unsafe.Offsetof(C.rustleaks_status_view{}.normalization_bytes) - unsafe.Offsetof(statusView{}.normalizationBytes)
)

// The constants in abi.go must equal the header's.
const (
	_ = uint(C.RUSTLEAKS_ABI_VERSION - abiVersion)
	_ = uint(abiVersion - C.RUSTLEAKS_ABI_VERSION)
	_ = uint(C.RUSTLEAKS_SCAN_SET_ALL - (scanSetDeadline<<1 - 1))
	_ = uint((scanSetDeadline<<1 - 1) - C.RUSTLEAKS_SCAN_SET_ALL)
	_ = uint(C.RUSTLEAKS_MAX_WORKERS - maxWorkers)
	_ = uint(maxWorkers - C.RUSTLEAKS_MAX_WORKERS)
	_ = uint(C.RUSTLEAKS_OPTION_WORKERS - optionWorkers)
	_ = uint(optionWorkers - C.RUSTLEAKS_OPTION_WORKERS)
	_ = uint(C.RUSTLEAKS_ERROR_PANIC - errorPanic)
	_ = uint(errorPanic - C.RUSTLEAKS_ERROR_PANIC)
)

func bytePtr(p unsafe.Pointer) *C.uint8_t { return (*C.uint8_t)(p) }

func callABIVersion(out *uint32) int32 {
	return int32(C.rustleaks_abi_version((*C.uint32_t)(unsafe.Pointer(out))))
}

func callVersion(ptr *unsafe.Pointer, n *uintptr) int32 {
	return int32(C.rustleaks_version((**C.uint8_t)(unsafe.Pointer(ptr)), (*C.size_t)(unsafe.Pointer(n))))
}

func callOptionsNew(abi uint32, out *unsafe.Pointer) int32 {
	return int32(C.rustleaks_options_new(C.uint32_t(abi), (**C.rustleaks_options)(unsafe.Pointer(out))))
}

func callOptionsSetConfig(options, config unsafe.Pointer, n uintptr) int32 {
	return int32(C.rustleaks_options_set_config((*C.rustleaks_options)(options), bytePtr(config), C.size_t(n)))
}

func callOptionsAddRuleID(options, id unsafe.Pointer, n uintptr) int32 {
	return int32(C.rustleaks_options_add_rule_id((*C.rustleaks_options)(options), bytePtr(id), C.size_t(n)))
}

func callOptionsSetU64(options unsafe.Pointer, key uint32, value uint64) int32 {
	return int32(C.rustleaks_options_set_u64((*C.rustleaks_options)(options), C.uint32_t(key), C.uint64_t(value)))
}

func callOptionsSetBool(options unsafe.Pointer, key uint32, value uint8) int32 {
	return int32(C.rustleaks_options_set_bool((*C.rustleaks_options)(options), C.uint32_t(key), C.uint8_t(value)))
}

func callOptionsFree(options unsafe.Pointer) int32 {
	return int32(C.rustleaks_options_free((*C.rustleaks_options)(options)))
}

func callEngineNew(options unsafe.Pointer, out, failure *unsafe.Pointer) int32 {
	return int32(C.rustleaks_engine_new(
		(*C.rustleaks_options)(options),
		(**C.rustleaks_engine)(unsafe.Pointer(out)),
		(**C.rustleaks_error)(unsafe.Pointer(failure)),
	))
}

func callEngineFree(engine unsafe.Pointer) int32 {
	return int32(C.rustleaks_engine_free((*C.rustleaks_engine)(engine)))
}

func callEngineWorkers(engine unsafe.Pointer, out *uintptr) int32 {
	return int32(C.rustleaks_engine_workers((*C.rustleaks_engine)(engine), (*C.size_t)(unsafe.Pointer(out))))
}

func callEngineMaxInputBytes(engine unsafe.Pointer, out *uint64) int32 {
	return int32(C.rustleaks_engine_max_input_bytes((*C.rustleaks_engine)(engine), (*C.uint64_t)(unsafe.Pointer(out))))
}

func callEngineRuleCount(engine unsafe.Pointer, out *uintptr) int32 {
	return int32(C.rustleaks_engine_rule_count((*C.rustleaks_engine)(engine), (*C.size_t)(unsafe.Pointer(out))))
}

func callEngineRule(engine unsafe.Pointer, index uintptr, out *ruleView) int32 {
	return int32(C.rustleaks_engine_rule(
		(*C.rustleaks_engine)(engine),
		C.size_t(index),
		(*C.rustleaks_rule_view)(unsafe.Pointer(out)),
	))
}

func callCancelNew(out *unsafe.Pointer) int32 {
	return int32(C.rustleaks_cancel_new((**C.rustleaks_cancel)(unsafe.Pointer(out))))
}

func callCancelSet(cancel unsafe.Pointer) int32 {
	return int32(C.rustleaks_cancel_set((*C.rustleaks_cancel)(cancel)))
}

func callCancelFree(cancel unsafe.Pointer) int32 {
	return int32(C.rustleaks_cancel_free((*C.rustleaks_cancel)(cancel)))
}

// callScan passes Go memory to C: the input bytes and args, whose path the
// caller has pinned. The library copies both before it returns.
func callScan(engine, input unsafe.Pointer, n uintptr, args *scanArgs, cancel unsafe.Pointer, out, failure *unsafe.Pointer) int32 {
	return int32(C.rustleaks_scan(
		(*C.rustleaks_engine)(engine),
		bytePtr(input),
		C.size_t(n),
		(*C.rustleaks_scan_args)(unsafe.Pointer(args)),
		(*C.rustleaks_cancel)(cancel),
		(**C.rustleaks_result)(unsafe.Pointer(out)),
		(**C.rustleaks_error)(unsafe.Pointer(failure)),
	))
}

func callResultStatus(result unsafe.Pointer, out *statusView) int32 {
	return int32(C.rustleaks_result_status((*C.rustleaks_result)(result), (*C.rustleaks_status_view)(unsafe.Pointer(out))))
}

func callResultCount(result unsafe.Pointer, out *uintptr) int32 {
	return int32(C.rustleaks_result_count((*C.rustleaks_result)(result), (*C.size_t)(unsafe.Pointer(out))))
}

func callResultFinding(result unsafe.Pointer, index uintptr, out *findingView) int32 {
	return int32(C.rustleaks_result_finding(
		(*C.rustleaks_result)(result),
		C.size_t(index),
		(*C.rustleaks_finding_view)(unsafe.Pointer(out)),
	))
}

func callResultFree(result unsafe.Pointer) int32 {
	return int32(C.rustleaks_result_free((*C.rustleaks_result)(result)))
}

func callErrorKind(failure unsafe.Pointer, out *int32) int32 {
	return int32(C.rustleaks_error_kind((*C.rustleaks_error)(failure), (*C.int32_t)(unsafe.Pointer(out))))
}

func callErrorMessage(failure unsafe.Pointer, ptr *unsafe.Pointer, n *uintptr) int32 {
	return int32(C.rustleaks_error_message(
		(*C.rustleaks_error)(failure),
		(**C.uint8_t)(unsafe.Pointer(ptr)),
		(*C.size_t)(unsafe.Pointer(n)),
	))
}

func callErrorFree(failure unsafe.Pointer) int32 {
	return int32(C.rustleaks_error_free((*C.rustleaks_error)(failure)))
}
