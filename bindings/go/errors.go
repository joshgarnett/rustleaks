package rustleaks

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"unsafe"
)

// ErrClosed is returned by a scan on an engine that Close has closed or is
// closing.
var ErrClosed = errors.New("rustleaks: engine is closed")

// ErrInputTooLarge is returned, wrapped with the sizes, for an input longer
// than the engine's input limit. See WithMaxInputBytes.
var ErrInputTooLarge = errors.New("rustleaks: input is larger than the input limit")

// ConfigErrorKind says why New could not build an engine.
type ConfigErrorKind int

const (
	// KindConfig means the configuration could not be loaded, for example
	// because it is not valid TOML, a pattern does not compile, or it uses
	// [extend] path.
	KindConfig ConfigErrorKind = iota + 1
	// KindRuleSelection means a rule ID given to WithRules does not exist,
	// or the selection is over a limit.
	KindRuleSelection
	// KindEngine means the engine could not be built from a valid
	// configuration, or a thread could not start.
	KindEngine
)

// String returns the kind name.
func (k ConfigErrorKind) String() string {
	switch k {
	case KindConfig:
		return "config"
	case KindRuleSelection:
		return "rule selection"
	case KindEngine:
		return "engine"
	default:
		return "ConfigErrorKind(" + strconv.Itoa(int(k)) + ")"
	}
}

// ConfigError is returned by New when the configuration, the rule selection
// or the engine build fails.
//
// Message is the full message from rustleaks-core. It can quote text from
// the configuration, so treat it as you would the configuration.
type ConfigError struct {
	Kind    ConfigErrorKind
	Message string
}

func (e *ConfigError) Error() string {
	return "rustleaks: " + e.Kind.String() + " error: " + e.Message
}

// Termination says why a scan stopped before it finished.
type Termination int

const (
	// TerminationCancelled means the context was cancelled.
	TerminationCancelled Termination = iota + 1
	// TerminationDeadline means the context deadline passed.
	TerminationDeadline
	// TerminationBudget means a budget ran out.
	TerminationBudget
	// TerminationOther means the library stopped the scan for a reason
	// that this version of the package does not name.
	TerminationOther
)

// String returns the termination name.
func (t Termination) String() string {
	switch t {
	case TerminationCancelled:
		return "cancelled"
	case TerminationDeadline:
		return "deadline exceeded"
	case TerminationBudget:
		return "budget exceeded"
	case TerminationOther:
		return "stopped"
	default:
		return "Termination(" + strconv.Itoa(int(t)) + ")"
	}
}

// Usage is what a scan used before it ended.
type Usage struct {
	DecodedBytes        uint64
	WorkUnits           uint64
	FindingRecords      uint64
	FindingPayloadBytes uint64
	CollectedSpans      uint64
	NormalizationBytes  uint64
}

// IncompleteError is returned when a scan stopped before it finished. The
// scan returns no findings with it, because partial findings are not a full
// result.
//
// For a cancelled context or a passed deadline, errors.Is(err,
// context.Canceled) or errors.Is(err, context.DeadlineExceeded) is true.
type IncompleteError struct {
	// Termination says why the scan stopped.
	Termination Termination
	// Budget, Limit, Consumed and Requested describe the budget that ran
	// out when Termination is TerminationBudget: its inclusive limit, the
	// units used before the step that did not fit, and the units that step
	// asked for. They are zero otherwise.
	Budget    BudgetKind
	Limit     uint64
	Consumed  uint64
	Requested uint64
	// Usage is what the scan used. It is zero when the scan stopped before
	// it started, for example while it waited for a worker.
	Usage Usage

	cause error
}

func (e *IncompleteError) Error() string {
	if e.Termination == TerminationBudget {
		return fmt.Sprintf("rustleaks: scan stopped: %s budget exceeded (limit %d, used %d, requested %d)",
			e.Budget, e.Limit, e.Consumed, e.Requested)
	}
	return "rustleaks: scan stopped: " + e.Termination.String()
}

// Unwrap returns context.Canceled or context.DeadlineExceeded when the
// context stopped the scan, and nil otherwise.
func (e *IncompleteError) Unwrap() error { return e.cause }

// contextError returns the IncompleteError for a context that is done.
func contextError(err error) *IncompleteError {
	if errors.Is(err, context.DeadlineExceeded) {
		return &IncompleteError{Termination: TerminationDeadline, cause: context.DeadlineExceeded}
	}
	return &IncompleteError{Termination: TerminationCancelled, cause: context.Canceled}
}

// LibraryError is returned when the native library cannot be loaded, has a
// different ABI number or version than this package, or fails in a way that
// a correct call does not cause, such as an internal panic.
type LibraryError struct {
	// Op is what the package was doing, such as "load".
	Op string
	// Path is the library path, when one is involved.
	Path string
	// Message describes the failure.
	Message string
	// Err is the underlying error, if any.
	Err error
}

func (e *LibraryError) Error() string {
	text := "rustleaks: " + e.Op + ": " + e.Message
	if e.Path != "" {
		text += " (" + e.Path + ")"
	}
	if e.Err != nil {
		text += ": " + e.Err.Error()
	}
	return text
}

// Unwrap returns the underlying error.
func (e *LibraryError) Unwrap() error { return e.Err }

// statusError turns a status without an error handle into an error.
func statusError(op string, status int32) error {
	return &LibraryError{Op: op, Message: statusText(status)}
}

func statusText(status int32) string {
	switch status {
	case errorInvalidArgument:
		return "the library rejected an argument"
	case errorABIMismatch:
		return "the library has a different ABI number"
	case errorPanic:
		return "the library caught an internal panic"
	default:
		return "the library returned status " + strconv.Itoa(int(status))
	}
}

// takeError reads and frees an error handle. It returns the status itself
// when the handle is null.
func takeError(failure unsafe.Pointer, status int32) (int32, string) {
	if failure == nil {
		return status, statusText(status)
	}
	defer callErrorFree(failure)
	kind := status
	if callErrorKind(failure, &kind) != statusOK {
		kind = status
	}
	var ptr unsafe.Pointer
	var n uintptr
	message := statusText(kind)
	if callErrorMessage(failure, &ptr, &n) == statusOK {
		message = nativeString(nativeBytes{ptr: ptr, len: n})
	}
	return kind, message
}
