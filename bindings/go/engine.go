package rustleaks

import (
	"context"
	"errors"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"time"
	"unsafe"
)

// Engine scans bytes for secrets with a fixed set of rules.
//
// An Engine is safe for concurrent use. Build it once and reuse it, because
// building it compiles every rule. Up to Workers scans run at once; other
// callers wait for a free worker, and the wait honors their context. Call
// Close when you are done with it.
type Engine struct {
	native  unsafe.Pointer // the engine handle; nil after Close frees it
	workers int
	rules   []Rule
	byID    map[string]int
	// maxInput is the input limit when the caller set one. Otherwise the
	// library checks its own default.
	maxInput    uint64
	maxInputSet bool

	slots   chan struct{} // one value for each running scan
	closing chan struct{} // closed when Close starts

	mu        sync.Mutex
	closed    bool
	active    sync.WaitGroup // scans that started before Close
	closeOnce sync.Once
	closeErr  error
	cleanup   runtime.Cleanup
}

// New builds an engine. With no options it uses every built-in rule, the
// same rules as the rustleaks command, and the library defaults: decode
// depth 0, allow comments honored, an input limit of 10,000,000 bytes and a
// limit of 100,000 findings.
//
// New returns a *ConfigError when the configuration, the rule selection or
// the build fails, and a *LibraryError when the native library cannot be
// loaded or does not match this package.
func New(opts ...Option) (*Engine, error) {
	var settings engineSettings
	for _, opt := range opts {
		if opt != nil {
			opt.applyEngine(&settings)
		}
	}
	if err := settings.err(); err != nil {
		return nil, err
	}
	if err := ensureLibrary(); err != nil {
		return nil, err
	}
	native, err := buildEngine(&settings)
	if err != nil {
		return nil, err
	}
	e := &Engine{
		native:      native,
		maxInput:    settings.maxInputBytes.value,
		maxInputSet: settings.maxInputBytes.set,
		closing:     make(chan struct{}),
	}
	if err := e.readEngine(); err != nil {
		callEngineFree(native)
		return nil, err
	}
	e.slots = make(chan struct{}, e.workers)
	// A leaked engine frees its native engine when the garbage collector
	// finds it unreachable. Close is still the way to free it.
	e.cleanup = runtime.AddCleanup(e, freeLeakedEngine, native)
	return e, nil
}

// Test hooks. They are nil outside the package tests.
var (
	// testHookBeforeNativeScan runs after a scan has a worker and its
	// cancel handle, right before the native call.
	testHookBeforeNativeScan func()
	// testHookLeakFreed runs after the cleanup of a leaked engine.
	testHookLeakFreed func()
)

func freeLeakedEngine(native unsafe.Pointer) {
	callEngineFree(native)
	if hook := testHookLeakFreed; hook != nil {
		hook()
	}
}

// buildEngine creates the options handle, sets every option the caller
// set, and builds the native engine.
func buildEngine(s *engineSettings) (unsafe.Pointer, error) {
	var options unsafe.Pointer
	if status := callOptionsNew(abiVersion, &options); status != statusOK {
		if status == errorABIMismatch {
			return nil, &LibraryError{Op: "create engine", Message: "the library has a different ABI number than this package"}
		}
		return nil, statusError("create engine options", status)
	}
	defer func() {
		handle := options
		options = nil
		callOptionsFree(handle)
	}()
	set := func(op string, status int32) error {
		if status != statusOK {
			return statusError(op, status)
		}
		return nil
	}
	if s.hasConfig {
		status := callOptionsSetConfig(options, bytesPointer(s.config), uintptr(len(s.config)))
		runtime.KeepAlive(s.config)
		if err := set("set the configuration", status); err != nil {
			return nil, err
		}
	}
	for _, id := range s.rules {
		status := callOptionsAddRuleID(options, stringPointer(id), uintptr(len(id)))
		runtime.KeepAlive(id)
		if status == errorInvalidArgument {
			return nil, &ConfigError{Kind: KindRuleSelection, Message: "too many rule IDs"}
		}
		if err := set("add a rule ID", status); err != nil {
			return nil, err
		}
	}
	values := []struct {
		key   uint32
		value setting[uint64]
	}{
		{optionWorkers, s.workers},
		{optionMaxInputBytes, s.maxInputBytes},
		{optionDecodeDepth, s.detection.decodeDepth},
		{optionBase64Mode, setting[uint64]{uint64(s.detection.base64Mode.value), s.detection.base64Mode.set}},
		{optionRedactionPercent, s.detection.redactionPercent},
	}
	budgetKeys := [budgetKinds]uint32{
		optionMaxDecodedBytes, optionMaxWorkUnits, optionMaxFindingRecords,
		optionMaxFindingPayloadBytes, optionMaxCollectedSpans, optionMaxNormalizationBytes,
	}
	for i, key := range budgetKeys {
		values = append(values, struct {
			key   uint32
			value setting[uint64]
		}{key, s.detection.budgets[i]})
	}
	for _, v := range values {
		if v.value.set {
			if err := set("set an engine option", callOptionsSetU64(options, v.key, v.value.value)); err != nil {
				return nil, err
			}
		}
	}
	if s.detection.allowComments.set {
		if err := set("set allow comments", callOptionsSetBool(options, optionAllowComments, boolByte(s.detection.allowComments.value))); err != nil {
			return nil, err
		}
	}
	var native, failure unsafe.Pointer
	status := callEngineNew(options, &native, &failure)
	if status == statusOK {
		return native, nil
	}
	kind, message := takeError(failure, status)
	switch kind {
	case errorConfig:
		return nil, &ConfigError{Kind: KindConfig, Message: message}
	case errorRuleSelection:
		return nil, &ConfigError{Kind: KindRuleSelection, Message: message}
	case errorEngine:
		return nil, &ConfigError{Kind: KindEngine, Message: message}
	default:
		return nil, &LibraryError{Op: "create engine", Message: message}
	}
}

// readEngine reads the worker count and the rules.
func (e *Engine) readEngine() error {
	var workers uintptr
	if status := callEngineWorkers(e.native, &workers); status != statusOK {
		return statusError("read the worker count", status)
	}
	e.workers = max(int(workers), 1)
	var count uintptr
	if status := callEngineRuleCount(e.native, &count); status != statusOK {
		return statusError("read the rule count", status)
	}
	e.rules = make([]Rule, count)
	e.byID = make(map[string]int, count)
	for i := range e.rules {
		var view ruleView
		if status := callEngineRule(e.native, uintptr(i), &view); status != statusOK {
			return statusError("read a rule", status)
		}
		e.rules[i] = Rule{
			ID:          nativeString(view.id),
			Description: nativeString(view.description),
			Tags:        nativeStrings(view.tags, view.tagCount),
			Keywords:    nativeStrings(view.keywords, view.keywordCount),
		}
		e.byID[e.rules[i].ID] = i
	}
	return nil
}

// Rules returns the rules that can report findings, in report order. The
// result is a copy. Rules keeps working after Close.
func (e *Engine) Rules() []Rule {
	if e == nil {
		return nil
	}
	out := make([]Rule, len(e.rules))
	for i, rule := range e.rules {
		rule.Tags = slices.Clone(rule.Tags)
		rule.Keywords = slices.Clone(rule.Keywords)
		out[i] = rule
	}
	return out
}

// Workers returns how many scans of the engine can run at once.
func (e *Engine) Workers() int {
	if e == nil {
		return 0
	}
	return e.workers
}

// Close stops new scans and frees the engine after the scans that are
// running return. It does not cancel them; scans that wait for a worker
// return ErrClosed. Close can be called many times and from many
// goroutines. Every call returns after the engine is freed.
func (e *Engine) Close() error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	if !e.closed {
		e.closed = true
		if e.closing != nil {
			close(e.closing)
		}
	}
	e.mu.Unlock()
	e.closeOnce.Do(func() {
		e.active.Wait()
		e.cleanup.Stop()
		native := e.native
		e.native = nil
		if native != nil {
			if status := callEngineFree(native); status != statusOK {
				e.closeErr = statusError("free the engine", status)
			}
		}
	})
	return e.closeErr
}

// ScanString scans s and returns its findings in report order.
//
// The scan waits for a free worker first. It stops early when ctx is
// cancelled or its deadline passes, and then returns an *IncompleteError
// that wraps the context error. A scan that a budget stops also returns an
// *IncompleteError. ScanString never returns while the library still reads
// s.
func (e *Engine) ScanString(ctx context.Context, s string, opts ...ScanOption) ([]Finding, error) {
	return e.scan(ctx, stringPointer(s), len(s), opts)
}

// ScanBytes scans b and returns its findings in report order. See
// ScanString. The library copies b when the scan starts; do not change b
// until ScanBytes returns.
func (e *Engine) ScanBytes(ctx context.Context, b []byte, opts ...ScanOption) ([]Finding, error) {
	return e.scan(ctx, bytesPointer(b), len(b), opts)
}

var errNilContext = errors.New("rustleaks: nil context")

func (e *Engine) scan(ctx context.Context, input unsafe.Pointer, n int, opts []ScanOption) ([]Finding, error) {
	defer runtime.KeepAlive(input)
	if ctx == nil {
		return nil, errNilContext
	}
	var settings scanSettings
	for _, opt := range opts {
		if opt != nil {
			opt.applyScan(&settings)
		}
	}
	if err := settings.err(); err != nil {
		return nil, err
	}
	if e == nil {
		return nil, ErrClosed
	}
	if e.maxInputSet && e.maxInput != Unlimited && uint64(n) > e.maxInput {
		return nil, inputTooLarge(n, e.maxInput)
	}
	if err := ctx.Err(); err != nil {
		return nil, contextError(err)
	}

	e.mu.Lock()
	if e.closed || e.slots == nil {
		e.mu.Unlock()
		return nil, ErrClosed
	}
	e.active.Add(1)
	e.mu.Unlock()
	defer e.active.Done()

	select {
	case e.slots <- struct{}{}:
	case <-e.closing:
		return nil, ErrClosed
	case <-ctx.Done():
		return nil, contextError(ctx.Err())
	}
	defer func() { <-e.slots }()
	select {
	case <-e.closing:
		return nil, ErrClosed
	default:
	}
	return e.scanNative(ctx, input, n, &settings)
}

func inputTooLarge(n int, limit uint64) error {
	return &inputSizeError{message: "input is " + strconv.Itoa(n) + " bytes, more than the limit of " +
		strconv.FormatUint(limit, 10) + " bytes"}
}

// inputSizeError wraps ErrInputTooLarge with the sizes.
type inputSizeError struct{ message string }

func (e *inputSizeError) Error() string { return ErrInputTooLarge.Error() + ": " + e.message }
func (e *inputSizeError) Unwrap() error { return ErrInputTooLarge }

// scanNative runs one scan while the caller holds a worker slot.
func (e *Engine) scanNative(ctx context.Context, input unsafe.Pointer, n int, settings *scanSettings) ([]Finding, error) {
	args := scanArgs{allowComments: 1}
	applyScanDetection(&args, &settings.detection)

	// The args hold a pointer to the path, so the path must be pinned while
	// C can see it.
	var pinner runtime.Pinner
	defer pinner.Unpin()
	if settings.path != "" {
		path := unsafe.StringData(settings.path)
		pinner.Pin(path)
		args.path = unsafe.Pointer(path)
		args.pathLen = uintptr(len(settings.path))
	}

	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, contextError(context.DeadlineExceeded)
		}
		args.overrides |= scanSetDeadline
		args.deadlineNS = uint64(remaining)
	}

	// A context that can be cancelled gets a cancel handle. AfterFunc only
	// sets its flag; the scan sees it at its next check.
	var cancel unsafe.Pointer
	if ctx.Done() != nil {
		if status := callCancelNew(&cancel); status != statusOK {
			return nil, statusError("create a cancel handle", status)
		}
		done := make(chan struct{})
		stop := context.AfterFunc(ctx, func() {
			callCancelSet(cancel)
			close(done)
		})
		defer func() {
			if !stop() {
				<-done // the flag is being set; wait before freeing it
			}
			handle := cancel
			cancel = nil
			callCancelFree(handle)
		}()
	}

	if hook := testHookBeforeNativeScan; hook != nil {
		hook()
	}
	var result, failure unsafe.Pointer
	status := callScan(e.native, input, uintptr(n), &args, cancel, &result, &failure)
	runtime.KeepAlive(settings)
	if status != statusOK {
		kind, message := takeError(failure, status)
		if kind == errorInputTooLarge {
			return nil, &inputSizeError{message: message}
		}
		return nil, &LibraryError{Op: "scan", Message: message}
	}
	defer func() {
		handle := result
		result = nil
		callResultFree(handle)
	}()

	var scanStatus statusView
	if status := callResultStatus(result, &scanStatus); status != statusOK {
		return nil, statusError("read the scan status", status)
	}
	if scanStatus.termination != terminationComplete {
		return nil, incompleteError(ctx, &scanStatus)
	}
	return e.readFindings(result, settings.path)
}

func applyScanDetection(args *scanArgs, d *detectionSettings) {
	if d.decodeDepth.set {
		args.overrides |= scanSetDecodeDepth
		args.decodeDepth = d.decodeDepth.value
	}
	if d.base64Mode.set {
		args.overrides |= scanSetBase64Mode
		args.base64Mode = uint64(d.base64Mode.value)
	}
	if d.redactionPercent.set {
		args.overrides |= scanSetRedactionPercent
		args.redactionPercent = d.redactionPercent.value
	}
	if d.allowComments.set {
		args.overrides |= scanSetAllowComments
		args.allowComments = boolByte(d.allowComments.value)
	}
	budgets := [budgetKinds]struct {
		bit   uint64
		field *uint64
	}{
		{scanSetMaxDecodedBytes, &args.maxDecodedBytes},
		{scanSetMaxWorkUnits, &args.maxWorkUnits},
		{scanSetMaxFindingRecords, &args.maxFindingRecords},
		{scanSetMaxFindingPayloadBytes, &args.maxFindingPayloadBytes},
		{scanSetMaxCollectedSpans, &args.maxCollectedSpans},
		{scanSetMaxNormalizationBytes, &args.maxNormalizationBytes},
	}
	for i, budget := range budgets {
		if d.budgets[i].set {
			args.overrides |= budget.bit
			*budget.field = d.budgets[i].value
		}
	}
}

func incompleteError(ctx context.Context, s *statusView) *IncompleteError {
	err := &IncompleteError{
		Usage: Usage{
			DecodedBytes:        s.decodedBytes,
			WorkUnits:           s.workUnits,
			FindingRecords:      s.findingRecords,
			FindingPayloadBytes: s.findingPayloadBytes,
			CollectedSpans:      s.collectedSpans,
			NormalizationBytes:  s.normalizationBytes,
		},
	}
	switch s.termination {
	case terminationCancelled:
		// Only the context sets the flag. It may have been cancelled by its
		// own deadline timer.
		stopped := contextError(ctx.Err())
		err.Termination, err.cause = stopped.Termination, stopped.cause
	case terminationDeadline:
		err.Termination = TerminationDeadline
		err.cause = context.DeadlineExceeded
	case terminationBudget:
		err.Termination = TerminationBudget
		err.Budget = BudgetKind(s.budget)
		err.Limit = s.limit
		err.Consumed = s.consumed
		err.Requested = s.requested
	default:
		err.Termination = TerminationOther
	}
	return err
}

// readFindings copies the findings of a result into Go values. Equal lines
// become one string, and rule IDs and descriptions reuse the strings
// read with the rules.
func (e *Engine) readFindings(result unsafe.Pointer, path string) ([]Finding, error) {
	var count uintptr
	if status := callResultCount(result, &count); status != statusOK {
		return nil, statusError("read the finding count", status)
	}
	if count == 0 {
		return nil, nil
	}
	findings := make([]Finding, count)
	var lines lineCache
	for i := range findings {
		var view findingView
		if status := callResultFinding(result, uintptr(i), &view); status != statusOK {
			return nil, statusError("read a finding", status)
		}
		f := &findings[i]
		f.RuleID, f.Description = e.ruleText(view.ruleID, view.description)
		f.Tags = nativeStrings(view.tags, view.tagCount)
		f.Secret = nativeString(view.secret)
		f.Match = nativeString(view.matchText)
		f.Line = lines.line(view.line)
		if view.path.len == uintptr(len(path)) {
			f.Path = path
		} else {
			f.Path = nativeString(view.path)
		}
		f.StartLine = int(view.startLine)
		f.EndLine = int(view.endLine)
		f.StartColumn = int(view.startColumn)
		f.EndColumn = int(view.endColumn)
		f.SecretRange = nativeRange(view.secretStart, view.secretEnd, view.secretRangeExact)
		f.MatchRange = nativeRange(view.matchStart, view.matchEnd, view.matchRangeExact)
		f.Entropy = view.entropy
	}
	return findings, nil
}

// lineCache gives findings of one result with equal lines one string. The
// library gives findings on one line of 4096 bytes or more the same buffer,
// so those are found by pointer and length without reading them. Shorter
// lines have their own buffers and are found by content; the map lookup
// with a converted byte slice does not allocate.
type lineCache struct {
	byView    map[nativeBytes]string
	byContent map[string]string
}

const shortLine = 4096

func (c *lineCache) line(view nativeBytes) string {
	if view.len == 0 || view.ptr == nil {
		return ""
	}
	if line, ok := c.byView[view]; ok {
		return line
	}
	if view.len < shortLine {
		if line, ok := c.byContent[string(unsafe.Slice((*byte)(view.ptr), view.len))]; ok {
			return line
		}
	}
	line := nativeString(view)
	if c.byView == nil {
		c.byView = make(map[nativeBytes]string)
		c.byContent = make(map[string]string)
	}
	c.byView[view] = line
	if view.len < shortLine {
		c.byContent[line] = line
	}
	return line
}

func (e *Engine) ruleText(id, description nativeBytes) (string, string) {
	if id.len > 0 {
		if i, ok := e.byID[string(unsafe.Slice((*byte)(id.ptr), id.len))]; ok {
			rule := &e.rules[i]
			if description.len == uintptr(len(rule.Description)) &&
				(description.len == 0 || string(unsafe.Slice((*byte)(description.ptr), description.len)) == rule.Description) {
				return rule.ID, rule.Description
			}
			return rule.ID, nativeString(description)
		}
	}
	return nativeString(id), nativeString(description)
}

func nativeRange(start, end uint64, exact uint8) Range {
	if exact != 1 {
		return Range{}
	}
	return Range{Start: int(start), End: int(end), OK: true}
}

func boolByte(v bool) uint8 {
	if v {
		return 1
	}
	return 0
}
