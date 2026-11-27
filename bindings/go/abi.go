package rustleaks

import "unsafe"

// The numbers and struct layouts of the C ABI in rustleaks.h. The cgo layer
// checks at compile time that these structs have the C sizes and offsets.

// abiVersion is the ABI number this package was written for.
const abiVersion = 1

// Status and error kinds.
const (
	statusOK             = 0
	errorInvalidArgument = 1
	errorABIMismatch     = 2
	errorConfig          = 3
	errorRuleSelection   = 4
	errorEngine          = 5
	errorInputTooLarge   = 6
	errorPanic           = 8
)

// Keys for rustleaks_options_set_u64.
const (
	optionDecodeDepth            = 1
	optionBase64Mode             = 2
	optionRedactionPercent       = 3
	optionMaxInputBytes          = 4
	optionMaxDecodedBytes        = 5
	optionMaxWorkUnits           = 6
	optionMaxFindingRecords      = 7
	optionMaxFindingPayloadBytes = 8
	optionMaxCollectedSpans      = 9
	optionMaxNormalizationBytes  = 10
	optionWorkers                = 11
	maxWorkers                   = 256
)

// Keys for rustleaks_options_set_bool.
const optionAllowComments = 1

// Bits of scanArgs.overrides.
const (
	scanSetDecodeDepth            = 1 << 0
	scanSetBase64Mode             = 1 << 1
	scanSetRedactionPercent       = 1 << 2
	scanSetAllowComments          = 1 << 3
	scanSetMaxDecodedBytes        = 1 << 4
	scanSetMaxWorkUnits           = 1 << 5
	scanSetMaxFindingRecords      = 1 << 6
	scanSetMaxFindingPayloadBytes = 1 << 7
	scanSetMaxCollectedSpans      = 1 << 8
	scanSetMaxNormalizationBytes  = 1 << 9
	scanSetDeadline               = 1 << 10
)

// rustleaks_status_view.termination values.
const (
	terminationComplete  = 0
	terminationCancelled = 1
	terminationDeadline  = 2
	terminationBudget    = 3
)

// nativeBytes is rustleaks_bytes.
type nativeBytes struct {
	ptr unsafe.Pointer
	len uintptr
}

// scanArgs is rustleaks_scan_args.
type scanArgs struct {
	path                   unsafe.Pointer
	pathLen                uintptr
	overrides              uint64
	decodeDepth            uint64
	base64Mode             uint64
	redactionPercent       uint64
	maxDecodedBytes        uint64
	maxWorkUnits           uint64
	maxFindingRecords      uint64
	maxFindingPayloadBytes uint64
	maxCollectedSpans      uint64
	maxNormalizationBytes  uint64
	deadlineNS             uint64
	allowComments          uint8
}

// ruleView is rustleaks_rule_view.
type ruleView struct {
	id           nativeBytes
	description  nativeBytes
	tags         unsafe.Pointer
	tagCount     uintptr
	keywords     unsafe.Pointer
	keywordCount uintptr
}

// findingView is rustleaks_finding_view.
type findingView struct {
	ruleID           nativeBytes
	description      nativeBytes
	tags             unsafe.Pointer
	tagCount         uintptr
	secret           nativeBytes
	matchText        nativeBytes
	line             nativeBytes
	path             nativeBytes
	startLine        uint64
	endLine          uint64
	startColumn      uint64
	endColumn        uint64
	secretStart      uint64
	secretEnd        uint64
	matchStart       uint64
	matchEnd         uint64
	entropy          float64
	secretRangeExact uint8
	matchRangeExact  uint8
}

// statusView is rustleaks_status_view.
type statusView struct {
	termination         int32
	budget              int32
	limit               uint64
	consumed            uint64
	requested           uint64
	decodedBytes        uint64
	workUnits           uint64
	findingRecords      uint64
	findingPayloadBytes uint64
	collectedSpans      uint64
	normalizationBytes  uint64
}

// nativeString copies bytes that the library owns into a Go string.
func nativeString(b nativeBytes) string {
	if b.len == 0 || b.ptr == nil {
		return ""
	}
	return string(unsafe.Slice((*byte)(b.ptr), b.len))
}

// nativeStrings copies a list of rustleaks_bytes into Go strings.
func nativeStrings(list unsafe.Pointer, count uintptr) []string {
	if count == 0 || list == nil {
		return nil
	}
	views := unsafe.Slice((*nativeBytes)(list), count)
	out := make([]string, len(views))
	for i, view := range views {
		out[i] = nativeString(view)
	}
	return out
}

// bytesPointer returns the address of the first byte of b, or nil when b is
// empty, as the ABI expects for a length of 0.
func bytesPointer(b []byte) unsafe.Pointer {
	if len(b) == 0 {
		return nil
	}
	return unsafe.Pointer(unsafe.SliceData(b))
}

// stringPointer returns the address of the first byte of s, or nil when s
// is empty.
func stringPointer(s string) unsafe.Pointer {
	if len(s) == 0 {
		return nil
	}
	return unsafe.Pointer(unsafe.StringData(s))
}
