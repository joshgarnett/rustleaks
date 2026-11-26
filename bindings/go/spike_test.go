package rustleaks

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// stackChildEnv makes the test binary run one stack probe and exit. The
// parent test runs each probe in a child process, because a stack overflow
// in native code ends the whole process.
const stackChildEnv = "RUSTLEAKS_SPIKE_STACK_CHILD"

// expectedStackSums maps a probe size in KiB to the value spike_stack returns.
var expectedStackSums = map[uint32]uint64{64: 120, 256: 2016, 1024: 32640}

func TestMain(m *testing.M) {
	if err := loadLibrary(libraryPath()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if value := os.Getenv(stackChildEnv); value != "" {
		os.Exit(runStackChild(value))
	}
	os.Exit(m.Run())
}

// libraryPath returns the absolute DLL path on Windows. Bazel passes the
// runfiles paths of the shared library outputs in RUSTLEAKS_SPIKE_LIBRARY.
func libraryPath() string {
	if runtime.GOOS != "windows" {
		return ""
	}
	for _, path := range strings.Fields(os.Getenv("RUSTLEAKS_SPIKE_LIBRARY")) {
		if strings.HasSuffix(path, ".dll") {
			return filepath.Join(os.Getenv("TEST_SRCDIR"), filepath.FromSlash(path))
		}
	}
	return ""
}

func TestAdd(t *testing.T) {
	if got := spikeAdd(2, 40); got != 42 {
		t.Fatalf("spikeAdd(2, 40) = %d, want 42", got)
	}
	if got := spikeAdd(^uint64(0), 2); got != 1 {
		t.Fatalf("spikeAdd(max, 2) = %d, want 1", got)
	}
}

func TestSum(t *testing.T) {
	if got := spikeSum(nil); got != 0 {
		t.Fatalf("spikeSum(nil) = %d, want 0", got)
	}
	data := bytes.Repeat([]byte{0xff}, 1<<20)
	runtime.GC()
	if got, want := spikeSum(data), uint64(0xff)<<20; got != want {
		t.Fatalf("spikeSum(1 MiB of 0xff) = %d, want %d", got, want)
	}
}

// TestStackProbe records how much native stack a call from a goroutine on a
// thread other than the main thread can use. It logs the result and does
// not fail, because the spike only measures it.
func TestStackProbe(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, kib := range []uint32{64, 256, 1024} {
		command := exec.Command(executable, "-test.run=^$")
		command.Env = append(os.Environ(), stackChildEnv+"="+strconv.FormatUint(uint64(kib), 10))
		output, err := command.CombinedOutput()
		status, detail := "ok", lastLine(output)
		if err != nil {
			status, detail = "failed ("+err.Error()+")", firstLine(output)
		}
		t.Logf("SPIKE-STACK go %s/%s %d KiB: %s: %s", runtime.GOOS, runtime.GOARCH, kib, status, detail)
	}
}

func runStackChild(value string) int {
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		fmt.Println(err)
		return 2
	}
	kib := uint32(parsed)
	done := make(chan string)
	go func() {
		runtime.LockOSThread()
		if main, known := onMainThread(); known && main {
			// This goroutine holds the main thread, so the next one runs on
			// another thread.
			inner := make(chan string)
			go func() {
				runtime.LockOSThread()
				inner <- probe(kib)
			}()
			done <- <-inner
			return
		}
		done <- probe(kib)
	}()
	result := <-done
	fmt.Println(result)
	if !strings.HasPrefix(result, "ok") {
		return 1
	}
	return 0
}

func probe(kib uint32) string {
	thread := "thread unknown"
	if main, known := onMainThread(); known {
		thread = "main thread " + strconv.FormatBool(main)
	}
	got := spikeStack(kib)
	if got != expectedStackSums[kib] {
		return fmt.Sprintf("wrong result %d (%s)", got, thread)
	}
	return "ok (" + thread + ")"
}

func firstLine(output []byte) string {
	line, _, _ := strings.Cut(strings.TrimSpace(string(output)), "\n")
	return strings.TrimSpace(line)
}

func lastLine(output []byte) string {
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}
