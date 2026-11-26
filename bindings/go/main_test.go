package rustleaks

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	if runtime.GOOS == "windows" {
		path, err := testLibraryPath()
		if err == nil {
			err = SetLibraryPath(path)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "rustleaks test library:", err)
			os.Exit(2)
		}
	}
	if os.Getenv(stackChildEnv) != "" {
		os.Exit(runStackChild())
	}
	os.Exit(m.Run())
}

// testLibraryPath returns the absolute path of the DLL that Bazel built.
// RUSTLEAKS_TEST_LIBRARY lists the runfiles paths of the shared library
// outputs.
func testLibraryPath() (string, error) {
	for _, path := range strings.Fields(os.Getenv("RUSTLEAKS_TEST_LIBRARY")) {
		if strings.HasSuffix(path, ".dll") {
			return rlocation(path)
		}
	}
	if path := os.Getenv(LibraryPathEnv); path != "" {
		return path, nil
	}
	return "", fmt.Errorf("RUSTLEAKS_TEST_LIBRARY names no DLL")
}

// repoFile returns the absolute path of a repository file in the test's
// runfiles, or, outside Bazel, relative to this folder.
func repoFile(t testing.TB, rel string) string {
	t.Helper()
	path, err := rlocation("_main/" + rel)
	if err != nil {
		path, err = filepath.Abs(filepath.Join("..", "..", filepath.FromSlash(rel)))
	}
	if err != nil {
		t.Fatal(err)
	}
	return path
}

// rlocation finds a runfiles path with the runfiles folder or manifest
// that Bazel gives the test.
func rlocation(path string) (string, error) {
	for _, root := range []string{os.Getenv("RUNFILES_DIR"), os.Getenv("TEST_SRCDIR")} {
		if root == "" {
			continue
		}
		candidate := filepath.Join(root, filepath.FromSlash(path))
		if _, err := os.Stat(candidate); err == nil {
			return filepath.Abs(candidate)
		}
	}
	if manifest := os.Getenv("RUNFILES_MANIFEST_FILE"); manifest != "" {
		f, err := os.Open(manifest)
		if err != nil {
			return "", err
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 64*1024), 1<<20)
		for scanner.Scan() {
			key, value, ok := strings.Cut(scanner.Text(), " ")
			if ok && key == path {
				return value, nil
			}
		}
	}
	return "", fmt.Errorf("runfile %s not found", path)
}
