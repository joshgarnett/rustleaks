package rustleaks

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// On musl, threads that Go starts for goroutines get a 128 KiB stack. The
// library builds engines and runs scans on its own threads with 8 MiB
// stacks, so a goroutine on any thread can build an engine and scan. The
// work runs in a child process, because a stack overflow in native code
// ends the whole process.

// stackChildEnv makes the test binary run the stack work and exit.
const stackChildEnv = "RUSTLEAKS_GO_STACK_CHILD"

func TestNativeStackFromGoroutine(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^$")
	command.Env = append(os.Environ(), stackChildEnv+"=1")
	output, err := command.CombinedOutput()
	text := strings.TrimSpace(string(output))
	if err != nil {
		t.Fatalf("child failed: %v\n%s", err, text)
	}
	if !strings.HasSuffix(text, "ok") {
		t.Fatalf("child output %q does not end with ok", text)
	}
	t.Log(text)
}

// nestedGroupsConfig returns a rule whose pattern has 200 nested groups,
// the most that core compiles on the scanning thread instead of its own.
func nestedGroupsConfig(depth int) []byte {
	pattern := strings.Repeat("(", depth) + "NEST-[0-9]{4}" + strings.Repeat(")", depth)
	return []byte(fmt.Sprintf("[[rules]]\nid = \"synthetic-nested\"\nregex = '''%s'''\nkeywords = [\"nest-\"]\n", pattern))
}

// runStackChild builds engines and scans from a goroutine on a thread that
// is not the main thread, and prints ok when every step worked.
func runStackChild() int {
	done := make(chan error)
	go func() {
		runtime.LockOSThread()
		if main, known := onMainThread(); known && main {
			// This goroutine holds the main thread, so the next one runs on
			// another thread.
			inner := make(chan error)
			go func() {
				runtime.LockOSThread()
				inner <- stackWork()
			}()
			done <- <-inner
			return
		}
		done <- stackWork()
	}()
	if err := <-done; err != nil {
		fmt.Println(err)
		return 1
	}
	fmt.Println("ok")
	return 0
}

func stackWork() error {
	thread := "thread unknown"
	if main, known := onMainThread(); known {
		thread = fmt.Sprintf("main thread %t", main)
	}
	ctx := context.Background()
	all, err := New()
	if err != nil {
		return fmt.Errorf("built-in rules (%s): %w", thread, err)
	}
	defer all.Close()
	key := "AKIA" + "LALEMEL33243OLIB"
	findings, err := all.ScanString(ctx, "aws_access_key_id = "+key+"\n"+strings.Repeat("filler text 0123456789 ", 4096))
	if err != nil {
		return fmt.Errorf("built-in scan (%s): %w", thread, err)
	}
	if !slices.ContainsFunc(findings, func(f Finding) bool { return f.RuleID == "aws-access-token" }) {
		return fmt.Errorf("built-in scan (%s): findings %v", thread, findings)
	}
	nested, err := New(WithConfig(nestedGroupsConfig(200)))
	if err != nil {
		return fmt.Errorf("nested groups (%s): %w", thread, err)
	}
	defer nested.Close()
	findings, err = nested.ScanString(ctx, "x NEST-1234 y\n")
	if err != nil {
		return fmt.Errorf("nested scan (%s): %w", thread, err)
	}
	if len(findings) != 1 || findings[0].Secret != "NEST-1234" {
		return fmt.Errorf("nested scan (%s): findings %v", thread, findings)
	}
	fmt.Printf("built-in and nested-group scans worked (%s, %s/%s)\n", thread, runtime.GOOS, runtime.GOARCH)
	return nil
}
