package rustleaks

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
)

// markerConfig has one synthetic rule. The secret is the four letters after
// "MARK-".
const markerConfig = `
[[rules]]
id = "synthetic-marker"
description = "A synthetic marker"
regex = '''MARK-([A-Z]{4})'''
secretGroup = 1
keywords = ["mark-"]
tags = ["synthetic"]
`

// awsKey returns a synthetic AWS access key ID. It is built at run time so
// that this file holds no complete key.
func awsKey() string { return "AKIA" + "LALEMEL33243OLIB" }

func newEngine(t testing.TB, opts ...Option) *Engine {
	t.Helper()
	e, err := New(opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := e.Close(); err != nil {
			t.Error(err)
		}
	})
	return e
}

func markerEngine(t testing.TB, opts ...Option) *Engine {
	t.Helper()
	return newEngine(t, append([]Option{WithConfig([]byte(markerConfig))}, opts...)...)
}

func setHook[F any](t *testing.T, target *F, hook F) {
	t.Helper()
	*target = hook
	t.Cleanup(func() {
		var zero F
		*target = zero
	})
}

func TestBuiltInRulesByDefault(t *testing.T) {
	e := newEngine(t)
	rules := e.Rules()
	ids := make([]string, len(rules))
	for i, rule := range rules {
		ids[i] = rule.ID
	}
	for _, id := range []string{"aws-access-token", "pkcs12-file", "generic-api-key"} {
		if !slices.Contains(ids, id) {
			t.Errorf("Rules() has no %s", id)
		}
	}
	if w := e.Workers(); w < 1 || w > 12 {
		t.Errorf("Workers() = %d, want 1 to 12 by default", w)
	}
	findings, err := e.ScanString(context.Background(), "string AWSToken = \""+awsKey()+"\";")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].RuleID != "aws-access-token" {
		t.Fatalf("findings %v, want one aws-access-token", findings)
	}
	if f := findings[0]; f.StartLine != 1 || f.StartColumn != 20 || f.EndColumn != 39 {
		t.Errorf("position %v, want line 1 columns 20 to 39", f)
	}
}

func TestRulesListsConfigRulesAndIsACopy(t *testing.T) {
	e := markerEngine(t)
	rules := e.Rules()
	want := Rule{ID: "synthetic-marker", Description: "A synthetic marker", Tags: []string{"synthetic"}, Keywords: []string{"mark-"}}
	if len(rules) != 1 || rules[0].ID != want.ID || rules[0].Description != want.Description ||
		!slices.Equal(rules[0].Tags, want.Tags) || !slices.Equal(rules[0].Keywords, want.Keywords) {
		t.Fatalf("Rules() = %#v, want %#v", rules, want)
	}
	rules[0].ID = "changed"
	rules[0].Tags[0] = "changed"
	if again := e.Rules(); again[0].ID != want.ID || again[0].Tags[0] != "synthetic" {
		t.Fatalf("changing the result of Rules changed the engine: %#v", again)
	}
}

func TestFindingFields(t *testing.T) {
	e := markerEngine(t)
	findings, err := e.ScanString(context.Background(), "a MARK-ABCD b MARK-EFGH\n", WithPath("config/app.env"))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}
	f := findings[0]
	if f.Description != "A synthetic marker" || !slices.Equal(f.Tags, []string{"synthetic"}) {
		t.Errorf("description %q, tags %q", f.Description, f.Tags)
	}
	if f.MatchRange != (Range{Start: 2, End: 11, OK: true}) || f.SecretRange != (Range{Start: 7, End: 11, OK: true}) {
		t.Errorf("match range %v, secret range %v", f.MatchRange, f.SecretRange)
	}
	if f.Entropy != 2 {
		t.Errorf("entropy %v, want 2 for four different letters", f.Entropy)
	}
	if f.Path != "config/app.env" {
		t.Errorf("path %q", f.Path)
	}
	// Both findings are on one line, so they share one string.
	if findings[0].Line != "a MARK-ABCD b MARK-EFGH" || unsafe.StringData(findings[0].Line) != unsafe.StringData(findings[1].Line) {
		t.Errorf("lines %q and %q are not one shared string", findings[0].Line, findings[1].Line)
	}
	// A long line, which the library shares between findings, is also one
	// string.
	long := strings.Repeat("z", 5000)
	findings, err = e.ScanString(context.Background(), "x\n"+long+" MARK-ABCD MARK-EFGH "+long+"\ny\n")
	if err != nil || len(findings) != 2 {
		t.Fatalf("long line: %v, %v", findings, err)
	}
	if len(findings[0].Line) < 10000 || unsafe.StringData(findings[0].Line) != unsafe.StringData(findings[1].Line) {
		t.Error("findings on one long line do not share one string")
	}
	// Rule IDs reuse the strings read with the rules.
	if unsafe.StringData(findings[0].RuleID) != unsafe.StringData(e.rules[0].ID) {
		t.Error("the rule ID is not the engine's rule ID string")
	}
}

func TestEmptyAndNilInput(t *testing.T) {
	e := markerEngine(t)
	for _, input := range [][]byte{nil, {}} {
		findings, err := e.ScanBytes(context.Background(), input)
		if err != nil || findings != nil {
			t.Fatalf("ScanBytes(%v) = %v, %v", input, findings, err)
		}
	}
	if findings, err := e.ScanString(context.Background(), ""); err != nil || findings != nil {
		t.Fatalf("ScanString(\"\") = %v, %v", findings, err)
	}
}

func TestScanOptionsOverrideTheEngine(t *testing.T) {
	ctx := context.Background()
	e := markerEngine(t)
	// "id: MARK-ABCD okay" in base64.
	encoded := "aWQ6IE1BUkstQUJDRCBva2F5\n"
	if findings, _ := e.ScanString(ctx, encoded); len(findings) != 0 {
		t.Fatalf("decoded without WithDecodeDepth: %v", findings)
	}
	findings, err := e.ScanString(ctx, encoded, WithDecodeDepth(1))
	if err != nil || len(findings) != 1 || findings[0].Secret != "ABCD" {
		t.Fatalf("WithDecodeDepth(1): %v, %v", findings, err)
	}
	if !slices.ContainsFunc(findings[0].Tags, func(tag string) bool { return strings.HasPrefix(tag, "decoded:") }) {
		t.Errorf("tags %q have no decoded: tag", findings[0].Tags)
	}
	if findings[0].SecretRange.OK || findings[0].MatchRange.OK {
		t.Errorf("decoded text has exact ranges %v %v", findings[0].SecretRange, findings[0].MatchRange)
	}
	again, _ := e.ScanString(ctx, encoded)
	if len(again) != 0 {
		t.Fatal("a scan option changed the engine")
	}

	allowed := "MARK-ABCD # rustleaks:allow\n"
	if findings, _ := e.ScanString(ctx, allowed); len(findings) != 0 {
		t.Fatalf("allow comment not honored by default: %v", findings)
	}
	if findings, _ := e.ScanString(ctx, allowed, WithAllowComments(false)); len(findings) != 1 {
		t.Fatalf("WithAllowComments(false) on the scan: %v", findings)
	}
	strict := markerEngine(t, WithAllowComments(false))
	if findings, _ := strict.ScanString(ctx, allowed); len(findings) != 1 {
		t.Fatalf("WithAllowComments(false) on the engine: %v", findings)
	}
	if findings, _ := strict.ScanString(ctx, allowed, WithAllowComments(true)); len(findings) != 0 {
		t.Fatalf("WithAllowComments(true) on the scan: %v", findings)
	}
}

func TestRedaction(t *testing.T) {
	ctx := context.Background()
	e := markerEngine(t)
	input := "x MARK-ABCD y\n"
	plain, err := e.ScanString(ctx, input)
	if err != nil || len(plain) != 1 {
		t.Fatal(plain, err)
	}
	for _, percent := range []int{0, 25, 50, 75, 100} {
		native, err := e.ScanString(ctx, input, WithRedaction(percent))
		if err != nil || len(native) != 1 {
			t.Fatal(native, err)
		}
		local := plain[0].Redacted(percent)
		if native[0].Secret != local.Secret || native[0].Match != local.Match || native[0].Line != local.Line {
			t.Errorf("percent %d: library %q %q %q, Redacted %q %q %q", percent,
				native[0].Secret, native[0].Match, native[0].Line, local.Secret, local.Match, local.Line)
		}
	}
	if got := plain[0].Redacted(100); got.Secret != "REDACTED" || got.Match != "MARK-REDACTED" || got.Line != "x MARK-REDACTED y" {
		t.Errorf("Redacted(100) = %q %q %q", got.Secret, got.Match, got.Line)
	}
	if got := plain[0].Redacted(50); got.Secret != "AB..." {
		t.Errorf("Redacted(50).Secret = %q, want AB...", got.Secret)
	}
	if plain[0].Secret != "ABCD" {
		t.Error("Redacted changed the original")
	}
	decoded := Finding{Secret: "ABCD", Match: "MARK-ABCD", Line: "aWQ6IE1BUkstQUJDRCBva2F5", Tags: []string{"decoded:base64"}}
	if got := decoded.Redacted(100); got.Line != "REDACTED" {
		t.Errorf("decoded Redacted(100).Line = %q, want REDACTED", got.Line)
	}
}

func TestBudgetStopsTheScan(t *testing.T) {
	e := markerEngine(t)
	_, err := e.ScanString(context.Background(), "MARK-ABCD\n", WithBudget(BudgetWorkUnits, 0))
	var incomplete *IncompleteError
	if !errors.As(err, &incomplete) {
		t.Fatalf("error %v, want *IncompleteError", err)
	}
	if incomplete.Termination != TerminationBudget || incomplete.Budget != BudgetWorkUnits || incomplete.Limit != 0 || incomplete.Requested == 0 {
		t.Errorf("incomplete %+v", *incomplete)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		t.Error("a budget error wraps a context error")
	}
	if findings, err := e.ScanString(context.Background(), "MARK-ABCD\n", WithBudget(BudgetWorkUnits, Unlimited)); err != nil || len(findings) != 1 {
		t.Fatalf("Unlimited budget: %v, %v", findings, err)
	}
}

func TestInputLimit(t *testing.T) {
	ctx := context.Background()
	e := markerEngine(t)
	// The library's default limit is 10,000,000 bytes, inclusive.
	at := []byte(strings.Repeat("x", 9_999_990) + "MARK-ABCD\n")
	if findings, err := e.ScanBytes(ctx, at); err != nil || len(findings) != 1 {
		t.Fatalf("input at the default limit: %d findings, %v", len(findings), err)
	}
	// The package reads the limit from the library and rejects a longer
	// input before it waits for a worker or calls the library.
	if e.maxInput != 10_000_000 {
		t.Errorf("the engine reports an input limit of %d", e.maxInput)
	}
	called := false
	setHook(t, &testHookBeforeNativeScan, func() { called = true })
	over := append(at, '\n')
	if _, err := e.ScanBytes(ctx, over); !errors.Is(err, ErrInputTooLarge) || called {
		t.Fatalf("input over the default limit: %v, native call %t", err, called)
	}
	small := markerEngine(t, WithMaxInputBytes(4))
	if _, err := small.ScanString(ctx, "12345"); !errors.Is(err, ErrInputTooLarge) || called {
		t.Fatalf("input over a set limit: %v, native call %t", err, called)
	}
	if findings, err := small.ScanString(ctx, "1234"); err != nil || findings != nil || !called {
		t.Fatalf("input at a set limit: %v, %v, native call %t", findings, err, called)
	}
	unlimited := markerEngine(t, WithMaxInputBytes(Unlimited))
	if unlimited.maxInput != Unlimited {
		t.Errorf("Unlimited engine reports an input limit of %d", unlimited.maxInput)
	}
	if findings, err := unlimited.ScanBytes(ctx, over); err != nil || len(findings) != 1 {
		t.Fatalf("Unlimited input: %d findings, %v", len(findings), err)
	}
}

// TestLibraryInputLimitCheck calls the library with an input over the limit
// directly, past the package's own check, to cover the library's error.
func TestLibraryInputLimitCheck(t *testing.T) {
	e := markerEngine(t, WithMaxInputBytes(4))
	e.maxInput = Unlimited
	if _, err := e.ScanString(context.Background(), "12345"); !errors.Is(err, ErrInputTooLarge) {
		t.Fatalf("library input check: %v", err)
	}
}

func TestBadArgumentsFailBeforeTheLibrary(t *testing.T) {
	for name, opt := range map[string]Option{
		"WithRules()":          WithRules(),
		"WithRules(invalid)":   WithRules("\xff"),
		"WithWorkers(-1)":      WithWorkers(-1),
		"WithWorkers(257)":     WithWorkers(257),
		"WithDecodeDepth(-1)":  WithDecodeDepth(-1),
		"WithRedaction(-1)":    WithRedaction(-1),
		"WithRedaction(101)":   WithRedaction(101),
		"WithBase64Mode(2)":    WithBase64Mode(2),
		"WithBudget(0, 1)":     WithBudget(0, 1),
		"WithBudget(7, 1)":     WithBudget(7, 1),
		"WithBudget(-1, 1)":    WithBudget(-1, 1),
		"WithDecodeDepth(-10)": WithDecodeDepth(-10),
	} {
		if e, err := New(opt); err == nil {
			e.Close()
			t.Errorf("New(%s) succeeded", name)
		}
	}
	e := markerEngine(t)
	called := false
	setHook(t, &testHookBeforeNativeScan, func() { called = true })
	for name, opt := range map[string]ScanOption{
		"WithDecodeDepth(-1)": WithDecodeDepth(-1),
		"WithRedaction(200)":  WithRedaction(200),
		"WithBudget(9, 0)":    WithBudget(9, 0),
	} {
		if _, err := e.ScanString(context.Background(), "MARK-ABCD", opt); err == nil {
			t.Errorf("scan with %s succeeded", name)
		}
	}
	var nilContext context.Context
	if _, err := e.ScanString(nilContext, "MARK-ABCD"); err == nil {
		t.Error("scan with a nil context succeeded")
	}
	if called {
		t.Error("a bad argument reached the library")
	}
	// Nil options are skipped.
	if findings, err := e.ScanString(context.Background(), "MARK-ABCD", nil); err != nil || len(findings) != 1 {
		t.Errorf("nil scan option: %v, %v", findings, err)
	}
}

func TestWorkersOption(t *testing.T) {
	for _, n := range []int{1, 3} {
		if got := markerEngine(t, WithWorkers(n)).Workers(); got != n {
			t.Errorf("WithWorkers(%d): Workers() = %d", n, got)
		}
	}
}

func TestConcurrentScans(t *testing.T) {
	e := markerEngine(t, WithWorkers(2))
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for g := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 20 {
				input := strings.Repeat("x\n", g+i) + "MARK-ABCD\n"
				findings, err := e.ScanBytes(ctx, []byte(input), WithPath("file"))
				if err != nil {
					errs <- err
					return
				}
				if len(findings) != 1 || findings[0].StartLine != g+i+1 || findings[0].Path != "file" {
					errs <- fmt.Errorf("goroutine %d scan %d: findings %v", g, i, findings)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestCloseWaitsForRunningScansAndStopsNewOnes(t *testing.T) {
	e, err := New(WithConfig([]byte(markerConfig)), WithWorkers(1))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	var released atomic.Bool
	setHook(t, &testHookBeforeNativeScan, func() {
		once.Do(func() {
			close(started)
			<-release
			released.Store(true)
		})
	})

	running := make(chan error, 1)
	go func() {
		findings, err := e.ScanString(ctx, "MARK-ABCD\n")
		if err == nil && len(findings) != 1 {
			err = errors.New("the running scan lost its finding")
		}
		running <- err
	}()
	<-started

	// This scan is counted as active before Close starts, so it waits for
	// the only worker and Close wakes it.
	counted := make(chan struct{})
	setHook(t, &testHookBeforeSlotWait, func() { close(counted) })
	waiting := make(chan error, 1)
	go func() {
		_, err := e.ScanString(ctx, "MARK-ABCD\n")
		waiting <- err
	}()
	<-counted
	testHookBeforeSlotWait = nil

	// Close cannot return before the running scan is released, so each
	// Close records whether the release came first.
	closed := make(chan error, 3)
	for range 3 {
		go func() {
			err := e.Close()
			if err == nil && !released.Load() {
				err = errors.New("Close returned while a scan was running")
			}
			closed <- err
		}()
	}
	if err := <-waiting; !errors.Is(err, ErrClosed) {
		t.Fatalf("waiting scan: %v, want ErrClosed", err)
	}
	if _, err := e.ScanString(ctx, "MARK-ABCD\n"); !errors.Is(err, ErrClosed) {
		t.Fatalf("scan after Close: %v, want ErrClosed", err)
	}
	close(release)
	if err := <-running; err != nil {
		t.Fatalf("running scan: %v", err)
	}
	for range 3 {
		if err := <-closed; err != nil {
			t.Fatal(err)
		}
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if rules := e.Rules(); len(rules) != 1 {
		t.Errorf("Rules after Close: %v", rules)
	}
}

func TestNilEngine(t *testing.T) {
	var e *Engine
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.ScanString(context.Background(), "x"); !errors.Is(err, ErrClosed) {
		t.Fatalf("scan on a nil engine: %v", err)
	}
	if e.Rules() != nil || e.Workers() != 0 {
		t.Fatal("nil engine has rules or workers")
	}
}

func TestCancelBeforeScan(t *testing.T) {
	e := markerEngine(t)
	called := false
	setHook(t, &testHookBeforeNativeScan, func() { called = true })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := e.ScanString(ctx, "MARK-ABCD\n")
	checkStopped(t, err, TerminationCancelled, context.Canceled)
	if called {
		t.Error("a cancelled scan reached the library")
	}
}

// TestCancelInsideTheLibrary sets the cancel flag right before the native
// call, so the library itself must report the cancelled scan.
func TestCancelInsideTheLibrary(t *testing.T) {
	e := markerEngine(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var handle unsafe.Pointer
	setHook(t, &testHookNativeArgs, func(_ *scanArgs, c unsafe.Pointer) {
		handle = c
		cancel()
		if status := callCancelSet(c); status != statusOK {
			t.Errorf("rustleaks_cancel_set: status %d", status)
		}
	})
	_, err := e.ScanString(ctx, "MARK-ABCD\n")
	if handle == nil {
		t.Fatal("a cancellable context got no cancel handle")
	}
	checkStopped(t, err, TerminationCancelled, context.Canceled)
}

// TestDeadlineInsideTheLibrary gives the library a deadline that has
// already passed, so the library itself must report it.
func TestDeadlineInsideTheLibrary(t *testing.T) {
	e := markerEngine(t)
	var handle unsafe.Pointer
	setHook(t, &testHookNativeArgs, func(args *scanArgs, c unsafe.Pointer) {
		handle = c
		args.overrides |= scanSetDeadline
		args.deadlineNS = 0
	})
	_, err := e.ScanString(context.Background(), "MARK-ABCD\n")
	if handle != nil {
		t.Error("a context that cannot end got a cancel handle")
	}
	checkStopped(t, err, TerminationDeadline, context.DeadlineExceeded)
}

func TestDeadline(t *testing.T) {
	e := markerEngine(t)
	called := false
	setHook(t, &testHookBeforeNativeScan, func() { called = true })
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	_, err := e.ScanString(expired, "MARK-ABCD\n")
	checkStopped(t, err, TerminationDeadline, context.DeadlineExceeded)
	if called {
		t.Error("a scan past its deadline reached the library")
	}

	// A deadline far away passes through to the library and does not stop
	// a short scan.
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()
	var deadline uint64
	setHook(t, &testHookNativeArgs, func(args *scanArgs, _ unsafe.Pointer) {
		if args.overrides&scanSetDeadline != 0 {
			deadline = args.deadlineNS
		}
	})
	findings, err := e.ScanString(ctx, "MARK-ABCD\n")
	if err != nil || len(findings) != 1 {
		t.Fatalf("scan with a far deadline: %v, %v", findings, err)
	}
	if deadline == 0 || deadline > uint64(time.Hour) {
		t.Errorf("deadline_ns = %d, want up to one hour", deadline)
	}
}

func TestWaitForWorkerHonorsTheContext(t *testing.T) {
	e := markerEngine(t, WithWorkers(1))
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	setHook(t, &testHookBeforeNativeScan, func() {
		once.Do(func() {
			close(started)
			<-release
		})
	})
	done := make(chan error, 1)
	go func() {
		_, err := e.ScanString(context.Background(), "MARK-ABCD\n")
		done <- err
	}()
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := e.ScanString(ctx, "MARK-ABCD\n")
	incomplete := checkStopped(t, err, TerminationDeadline, context.DeadlineExceeded)
	if incomplete != nil && incomplete.Usage != (Usage{}) {
		t.Errorf("a scan that never started has usage %+v", incomplete.Usage)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func checkStopped(t *testing.T, err error, want Termination, cause error) *IncompleteError {
	t.Helper()
	var incomplete *IncompleteError
	if !errors.As(err, &incomplete) {
		t.Fatalf("error %v, want *IncompleteError", err)
	}
	if incomplete.Termination != want {
		t.Errorf("termination %v, want %v", incomplete.Termination, want)
	}
	if !errors.Is(err, cause) {
		t.Errorf("errors.Is(%v, %v) is false", err, cause)
	}
	return incomplete
}

func TestGarbageCollectionAroundCalls(t *testing.T) {
	e := markerEngine(t, WithWorkers(4))
	setHook(t, &testHookBeforeNativeScan, runtime.GC)
	stop := make(chan struct{})
	collector := make(chan struct{})
	go func() {
		defer close(collector)
		for {
			select {
			case <-stop:
				return
			default:
				runtime.GC()
			}
		}
	}()
	var wg sync.WaitGroup
	for g := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 25 {
				input := []byte(strings.Repeat("y", g*100+i) + " MARK-ABCD MARK-EFGH\n")
				path := strings.Repeat("p", i+1)
				findings, err := e.ScanBytes(context.Background(), input, WithPath(path))
				runtime.GC()
				if err != nil || len(findings) != 2 || findings[1].Secret != "EFGH" || findings[1].Path != path {
					t.Errorf("scan %d/%d: %v, %v", g, i, findings, err)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(stop)
	<-collector
}

func TestLeakedEngineIsFreed(t *testing.T) {
	freed := make(chan struct{}, 1)
	setHook(t, &testHookLeakFreed, func() {
		select {
		case freed <- struct{}{}:
		default:
		}
	})
	func() {
		e, err := New(WithConfig([]byte(markerConfig)))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.ScanString(context.Background(), "MARK-ABCD"); err != nil {
			t.Fatal(err)
		}
	}()
	deadline := time.After(10 * time.Second)
	for {
		runtime.GC()
		select {
		case <-freed:
			return
		case <-deadline:
			t.Fatal("the cleanup did not free a leaked engine")
		case <-time.After(10 * time.Millisecond):
		}
	}
}
