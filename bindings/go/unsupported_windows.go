//go:build windows && !amd64 && !arm64

package rustleaks

// On Windows the package supports only x86_64 and ARM64. Its calls pass
// each argument as one 64-bit word, which is wrong on 32-bit systems, and
// no 32-bit DLL exists. A build for another architecture stops here.
var _ = rustleaks_supports_only_amd64_and_arm64_on_windows
