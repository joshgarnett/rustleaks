package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	gitleaksregexp "github.com/zricethezav/gitleaks/v8/regexp"
	"github.com/zricethezav/gitleaks/v8/report"
)

func TestRegexResourceContract(t *testing.T) {
	const searchBytes = 1 << 20

	data, err := os.ReadFile("../../../compat/regex-corpus/expressions-v1.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	var longest string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		var row struct {
			PatternBase64 string `json:"pattern_base64"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		pattern, err := base64.StdEncoding.DecodeString(row.PatternBase64)
		if err != nil {
			t.Fatal(err)
		}
		if len(pattern) > len(longest) {
			longest = string(pattern)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(longest) != 931 {
		t.Fatalf("longest default/fixture expression changed: %d", len(longest))
	}

	repeat1000 := regexp.MustCompile("a{1000}")
	deepSource := strings.Repeat("(?:", 4096) + "a" + strings.Repeat(")", 4096)
	deep := regexp.MustCompile(deepSource)
	largeClass := regexp.MustCompile("[" + strings.Repeat(`\x{3A9}`, 1000) + "]")
	longestRegex := regexp.MustCompile(longest)

	if !repeat1000.MatchString(strings.Repeat("a", 1000)) ||
		!deep.MatchString("a") || !largeClass.MatchString("Ω") ||
		longestRegex.MatchString(strings.Repeat("x", searchBytes)) {
		t.Fatal("resource workload result changed")
	}
}

func TestRequestMetadataRoundTripsArbitraryBytes(t *testing.T) {
	fragment, err := (requestFragment{
		ContentBase64:     "/w==",
		FileBase64:        "c3JjL/8=",
		WindowsFileBase64: "Qzpc/w==",
		AuthorBase64:      "Qf9C",
		RemotePlatform:    "none",
	}).decode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal([]byte(fragment.Raw), []byte{0xff}) ||
		!bytes.Equal([]byte(fragment.FilePath), []byte{'s', 'r', 'c', '/', 0xff}) ||
		!bytes.Equal([]byte(fragment.WindowsFilePath), []byte{'C', ':', '\\', 0xff}) ||
		!bytes.Equal([]byte(fragment.CommitInfo.AuthorName), []byte{'A', 0xff, 'B'}) {
		t.Fatalf("metadata bytes changed: %#v", fragment)
	}
}

func TestSourceProtocolPreservesFragmentBytesAndBoundarySemantics(t *testing.T) {
	boundary := safeRunSource(sourceRequest{
		ProtocolVersion: sourceProtocolVersion, ID: "boundary", Operation: "boundary",
		ContentBase64: b64("abcdefg\nhijklmnop\n\t  \t\nqrstuvwxyz"), BufferSize: 5, MaxPeekSize: 20,
	})
	if boundary.Error != nil || boundary.Platform == "" || len(boundary.Fragments) != 2 ||
		boundary.Fragments[0].RawBase64 != b64("abcdefg\nhijklmnop\n\t  \t\n") ||
		boundary.Fragments[0].BytesBase64 != boundary.Fragments[0].RawBase64 || boundary.Fragments[0].BytesNil ||
		boundary.Fragments[1].RawBase64 != b64("qrstuvwxyz") || boundary.Fragments[1].StartLine != 4 {
		t.Fatalf("boundary projection changed: %#v", boundary)
	}

	file := safeRunSource(sourceRequest{
		ProtocolVersion: sourceProtocolVersion, ID: "bytes", Operation: "file",
		ContentBase64: base64.StdEncoding.EncodeToString([]byte{0xff, 'x', '\n'}),
		PathBase64:    base64.StdEncoding.EncodeToString([]byte{'p', 0xff}), BufferSize: 100,
	})
	if file.Error != nil || len(file.Fragments) != 1 || file.Fragments[0].RawBase64 != file.Fragments[0].BytesBase64 ||
		file.Fragments[0].FileBase64 != base64.StdEncoding.EncodeToString([]byte{'p', 0xff}) || file.Fragments[0].BytesNil {
		t.Fatalf("file bytes changed: %#v", file)
	}
}

func TestSourceProtocolReaderErrorsAndVersionAreStructured(t *testing.T) {
	result := safeRunSource(sourceRequest{
		ProtocolVersion: sourceProtocolVersion, ID: "reader-error", Operation: "reader", Stream: true,
		ReaderSchedule: []sourceReaderStep{{Error: "error"}}, BufferSize: 1,
	})
	if result.Error != nil || len(result.Findings) != 0 || len(result.Issues) != 1 ||
		result.Issues[0].Class != "read" || result.ReadCalls != 1 {
		t.Fatalf("reader error projection changed: %#v", result)
	}
	wrong := safeRunSource(sourceRequest{ProtocolVersion: sourceProtocolVersion + 1})
	if wrong.Error == nil || wrong.Error.Class != "protocol" || wrong.Fragments == nil || wrong.Issues == nil {
		t.Fatalf("wrong source protocol accepted: %#v", wrong)
	}
	unknown := safeRunSource(sourceRequest{ProtocolVersion: sourceProtocolVersion, Operation: "unknown"})
	if unknown.Error == nil || unknown.Error.Class != "request" {
		t.Fatalf("unknown source operation accepted: %#v", unknown)
	}
}

func TestSourceProtocolTraversalAndSymlinkMetadata(t *testing.T) {
	result := safeRunSource(sourceRequest{
		ProtocolVersion: sourceProtocolVersion, ID: "symlink", Operation: "files", LogicalPath: "tree",
		FollowSymlinks: true, Entries: []sourceEntry{
			{Path: "target.txt", Kind: "file", ContentBase64: b64("target")},
			{Path: "link.txt", Kind: "symlink", Target: "target.txt"},
		},
	})
	if runtime.GOOS == "windows" {
		if result.Error != nil || len(result.Fragments) != 1 ||
			result.Fragments[0].FileBase64 != b64("tree/target.txt") || result.Fragments[0].SymlinkFileBase64 != "" {
			t.Fatalf("Windows symlink filtering changed: %#v", result)
		}
		return
	}
	if result.Error != nil || len(result.Fragments) != 2 {
		t.Fatalf("symlink traversal changed: %#v", result)
	}
	var sawLink bool
	for _, fragment := range result.Fragments {
		if fragment.SymlinkFileBase64 == b64("tree/link.txt") && fragment.FileBase64 == b64("tree/target.txt") {
			sawLink = true
		}
	}
	if !sawLink {
		t.Fatalf("symlink metadata missing: %#v", result.Fragments)
	}
}

func TestGitProtocolFreezesPinnedLogDiffAndMetadata(t *testing.T) {
	logResult := safeRunGit(gitRequest{
		ProtocolVersion: gitProtocolVersion, ID: "default-log", Operation: "log", Repository: "small",
	})
	if logResult.Error != nil || len(logResult.Issues) != 0 || len(logResult.Fragments) == 0 {
		t.Fatalf("default Git log failed: %#v", logResult)
	}
	var additions []byte
	var legacyAdditions []byte
	for _, fragment := range logResult.Fragments {
		raw, err := base64.StdEncoding.DecodeString(fragment.RawBase64)
		if err != nil {
			t.Fatal(err)
		}
		additions = append(additions, raw...)
		if string(mustDecodeBase64(t, fragment.CommitBase64)) != "53cd7a3c6eb4937f413e3c25e4a9f39289afa69e" {
			legacyAdditions = append(legacyAdditions, raw...)
		}
		if fragment.CommitInfo == nil || fragment.CommitInfo.SHABase64 != fragment.CommitBase64 {
			t.Fatalf("commit metadata missing: %#v", fragment)
		}
	}
	expected, err := os.ReadFile("../../../compat/fixtures/upstream/testdata/expected/git/small.txt")
	if err != nil {
		t.Fatal(err)
	}
	if len(additions) != 1477 || !bytes.Equal(legacyAdditions, expected) {
		t.Fatalf("default addition stream changed: got %d bytes; legacy-filtered %d, want %d", len(additions), len(legacyAdditions), len(expected))
	}
	wantArguments := []string{"git", "-C", "<repo>", "log", "-p", "-U0", "--full-history", "--all", "--diff-filter=tuxdb"}
	if !reflect.DeepEqual(logResult.ArgumentsBase64, b64Slice(wantArguments)) ||
		strings.Contains(string(mustDecodeBase64(t, logResult.CommandBase64)), "gitleaks git Ω oracle-") {
		t.Fatalf("Git command projection changed: %#v %q", logResult.ArgumentsBase64, mustDecodeBase64(t, logResult.CommandBase64))
	}

	diffResult := safeRunGit(gitRequest{
		ProtocolVersion: gitProtocolVersion, ID: "worktree", Operation: "diff", Repository: "small",
		Mutation: "working-additions",
	})
	if diffResult.Error != nil || len(diffResult.Fragments) != 1 ||
		string(mustDecodeBase64(t, diffResult.Fragments[0].RawBase64)) != "this line is added\nand another one" ||
		diffResult.Fragments[0].StartLine != 1 || string(mustDecodeBase64(t, diffResult.Fragments[0].FileBase64)) != "main.go" ||
		diffResult.Fragments[0].CommitInfo == nil || diffResult.Fragments[0].CommitInfo.SHABase64 != b64("") ||
		string(mustDecodeBase64(t, diffResult.Fragments[0].CommitInfo.DateBase64)) != "0001-01-01T00:00:00Z" {
		t.Fatalf("working-tree diff changed: %#v", diffResult)
	}
}

func TestGitProtocolFindingsArchiveAndCommitAllowlistObservation(t *testing.T) {
	detected := safeRunGit(gitRequest{
		ProtocolVersion: gitProtocolVersion, ID: "detect", Operation: "log", Repository: "small",
		Detect: true, ConfigFixture: "simple.toml", LoadIgnore: true,
	})
	if detected.Error != nil || len(detected.Findings) != 2 {
		t.Fatalf("small Git detection changed: %#v", detected)
	}
	for _, finding := range detected.Findings {
		if finding.CommitBase64 == b64("") || finding.AuthorBase64 == b64("") || finding.FingerprintBase64 == b64("") {
			t.Fatalf("incomplete Git finding: %#v", finding)
		}
	}

	allowed := safeRunGit(gitRequest{
		ProtocolVersion: gitProtocolVersion, ID: "allowed", Operation: "log", Repository: "small",
		LogOptions:   "-1 1b6da43b82b22e4eaa10bcf8ee591e91abbfc587",
		AllowCommits: []string{"1B6DA43B82B22E4EAA10BCF8EE591E91ABBFC587"},
	})
	// The pinned source's continue applies to the allowlist loop, not the file
	// loop. Freeze that observable quirk rather than silently fixing it here.
	if allowed.Error != nil || len(allowed.Fragments) != 1 {
		t.Fatalf("commit allowlist observation changed: %#v", allowed)
	}

	archive := safeRunGit(gitRequest{
		ProtocolVersion: gitProtocolVersion, ID: "archives", Operation: "log", Repository: "archives",
		Detect: true, ConfigFixture: "archives.toml", LoadIgnore: true, MaxArchiveDepth: 8,
	})
	if archive.Error != nil || len(archive.Findings) != 16 {
		t.Fatalf("binary archive Git expansion changed: error=%#v findings=%d issues=%#v", archive.Error, len(archive.Findings), archive.Issues)
	}
}

func TestGitProtocolSkipsAndClassifiesErrorsCancellationAndRemotes(t *testing.T) {
	for _, test := range []struct {
		id       string
		mutation string
		staged   bool
	}{
		{id: "delete", mutation: "delete-main"},
		{id: "binary", mutation: "binary-main"},
		{id: "rename", mutation: "staged-rename", staged: true},
	} {
		result := safeRunGit(gitRequest{ProtocolVersion: gitProtocolVersion, ID: test.id, Operation: "diff", Repository: "small", Mutation: test.mutation, Staged: test.staged})
		if result.Error != nil || len(result.Fragments) != 0 || len(result.Issues) != 0 {
			t.Fatalf("%s skip changed: %#v", test.id, result)
		}
	}

	malformed := safeRunGit(gitRequest{ProtocolVersion: gitProtocolVersion, ID: "malformed", Operation: "log", Repository: "empty"})
	if malformed.Error != nil || len(malformed.Fragments) != 1 || len(malformed.Issues) != 1 || malformed.Issues[0].Class != "stderr" {
		t.Fatalf("malformed repository classification changed: %#v", malformed)
	}
	canceled := safeRunGit(gitRequest{ProtocolVersion: gitProtocolVersion, ID: "cancel", Operation: "log", Repository: "small", CancelAfterStart: true})
	if canceled.Error == nil || canceled.Error.Class != "canceled" {
		t.Fatalf("Git cancellation changed: %#v", canceled)
	}
	workerError := safeRunGit(gitRequest{
		ProtocolVersion: gitProtocolVersion, ID: "worker-error", Operation: "diff", Repository: "small",
		Mutation: "staged-bad-archive", Staged: true, MaxArchiveDepth: 8,
	})
	if workerError.Error != nil || len(workerError.Fragments) != 0 || len(workerError.Issues) != 0 {
		t.Fatalf("Git worker-error loss changed: %#v", workerError)
	}
	remote := safeRunGit(gitRequest{
		ProtocolVersion: gitProtocolVersion, ID: "remote", Operation: "remote", Repository: "small",
		RemoteURL: "git@github.com:2222/org/repo.git", Platform: "unknown",
	})
	if remote.Error != nil || remote.Remote == nil || remote.Remote.Platform != "github" ||
		string(mustDecodeBase64(t, remote.Remote.URLBase64)) != "https://github.com/org/repo" {
		t.Fatalf("remote normalization changed: %#v", remote)
	}
	wroong := safeRunGit(gitRequest{ProtocolVersion: gitProtocolVersion + 1})
	if wroong.Error == nil || wroong.Error.Class != "protocol" || wroong.Fragments == nil || wroong.Issues == nil {
		t.Fatalf("wrong Git protocol accepted: %#v", wroong)
	}
}

func mustDecodeBase64(t *testing.T, encoded string) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestDirectDetectorProtocolPreservesBytesAndCompleteFindingShape(t *testing.T) {
	rawConfig := []byte(`[[rules]]
id = "direct"
description = "Direct detector"
regex = 'TOKEN=(....)'
keywords = ["token"]
tags = ["raw"]
`)
	content := []byte{0xff, 'T', 'O', 'K', 'E', 'N', '=', 'A', 'B', 'C', 'D'}
	result := safeRunDetect(detectRequest{
		ProtocolVersion: detectProtocolVersion,
		ID:              "direct-bytes",
		BehaviorIDs:     []string{"M4-RAW-BYTES-001"},
		TestCaseIDs:     []string{"TM-0073"},
		ConfigBase64:    base64.StdEncoding.EncodeToString(rawConfig),
		Fragment: requestFragment{
			ContentBase64:  base64.StdEncoding.EncodeToString(content),
			FileBase64:     base64.StdEncoding.EncodeToString([]byte{'s', 'r', 'c', '/', 0xff}),
			CommitBase64:   base64.StdEncoding.EncodeToString([]byte("abcdef1234567")),
			AuthorBase64:   base64.StdEncoding.EncodeToString([]byte{'A', 0xff}),
			RemotePlatform: "none",
		},
		Options: requestOptions{},
	})
	if result.Error != nil || result.OracleMode != "detect" || result.TotalBytes != uint64(len(content)) || len(result.Findings) != 1 {
		t.Fatalf("unexpected direct result: %#v", result)
	}
	finding := result.Findings[0]
	if finding.StartColumn != 2 || finding.EndColumn != 11 ||
		finding.LineBase64 != base64.StdEncoding.EncodeToString(content) ||
		finding.FileBase64 != base64.StdEncoding.EncodeToString([]byte{'s', 'r', 'c', '/', 0xff}) ||
		finding.AuthorBase64 != base64.StdEncoding.EncodeToString([]byte{'A', 0xff}) ||
		finding.Fragment != nil || finding.RequiredFindings == nil {
		t.Fatalf("direct finding lost bytes or shape: %#v", finding)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"fragment":null`, `"required_findings":[]`, `"fingerprint_base64":""`} {
		if !bytes.Contains(encoded, []byte(field)) {
			t.Fatalf("complete finding field %s missing from %s", field, encoded)
		}
	}
}

func TestDirectDetectorProtocolRejectsWrongVersion(t *testing.T) {
	result := safeRunDetect(detectRequest{ProtocolVersion: detectProtocolVersion + 1})
	if result.Error == nil || result.Error.Class != "protocol" || result.Findings == nil {
		t.Fatalf("wrong direct protocol accepted: %#v", result)
	}
}

func TestCompositeProtocolPreservesRequiredOrderAndMultiplicity(t *testing.T) {
	rawConfig := []byte(`[[rules]]
id = "primary"
regex = 'PRIMARY=([A-Z]+)'
[[rules.required]]
id = "aux"
[[rules.required]]
id = "aux"
[[rules]]
id = "aux"
regex = 'AUX=([a-z]+)'
skipReport = true
`)
	result := safeRunComposite(compositeRequest{
		ProtocolVersion: compositeProtocolVersion, ID: "required-order", Operation: "detect",
		BehaviorIDs: []string{"COMP-005"}, ConfigBase64: base64.StdEncoding.EncodeToString(rawConfig),
		Fragment: requestFragment{ContentBase64: base64.StdEncoding.EncodeToString([]byte("AUX=one AUX=two PRIMARY=VALUE"))},
		Options:  requestOptions{},
	})
	if result.Error != nil || len(result.Findings) != 1 || len(result.Findings[0].RequiredFindings) != 4 {
		t.Fatalf("composite projection changed: %#v", result)
	}
	want := []string{"one", "two", "one", "two"}
	for index, required := range result.Findings[0].RequiredFindings {
		secret, err := base64.StdEncoding.DecodeString(required.SecretBase64)
		if err != nil || string(secret) != want[index] || required.RuleID != "aux" {
			t.Fatalf("required order/multiplicity changed at %d: %#v", index, required)
		}
	}
	encoded, err := json.Marshal(result.Findings[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"required_findings"`, `"line_base64"`, `"match_base64"`, `"secret_base64"`} {
		if !bytes.Contains(encoded, []byte(field)) {
			t.Fatalf("required finding shape lost %s: %s", field, encoded)
		}
	}
}

func TestCompositeProtocolRedactPreservesBytesAndRejectsWrongVersion(t *testing.T) {
	result := safeRunComposite(compositeRequest{
		ProtocolVersion: compositeProtocolVersion, ID: "redact-bytes", Operation: "redact", RedactPercent: 50,
		Redaction: compositeFindingInput{
			RuleID: "rule", LineBase64: base64.StdEncoding.EncodeToString([]byte{'x', 0xff, 'y', 0xff}),
			MatchBase64:  base64.StdEncoding.EncodeToString([]byte{0xff, 'y', 0xff}),
			SecretBase64: base64.StdEncoding.EncodeToString([]byte{0xff}), EntropyBits: math.Float32bits(3.25),
			TagsBase64: []string{base64.StdEncoding.EncodeToString([]byte{0xfe})},
		},
	})
	if result.Error != nil || result.Original == nil || result.Redacted == nil ||
		result.Redacted.SecretBase64 != base64.StdEncoding.EncodeToString([]byte("...")) ||
		result.Redacted.LineBase64 != base64.StdEncoding.EncodeToString([]byte("x...y...")) ||
		result.Redacted.EntropyBits != math.Float32bits(3.25) {
		t.Fatalf("redaction bytes/invariants changed: %#v", result)
	}
	wrong := safeRunComposite(compositeRequest{ProtocolVersion: compositeProtocolVersion + 1})
	if wrong.Error == nil || wrong.Error.Class != "protocol" || wrong.Findings == nil {
		t.Fatalf("wrong composite protocol accepted: %#v", wrong)
	}
	unknown := safeRunComposite(compositeRequest{ProtocolVersion: compositeProtocolVersion, Operation: "unknown"})
	if unknown.Error == nil || unknown.Error.Class != "request" {
		t.Fatalf("unknown composite operation accepted: %#v", unknown)
	}
}

func TestCompositeProgrammaticMissingRequiredFailsClosed(t *testing.T) {
	result := safeRunComposite(compositeRequest{
		ProtocolVersion: compositeProtocolVersion, Operation: "probe_missing_required",
		Fragment: requestFragment{ContentBase64: base64.StdEncoding.EncodeToString([]byte("PRIMARY=VALUE"))},
	})
	if result.Error != nil || len(result.Findings) != 0 || result.ConfigSHA256 == "" {
		t.Fatalf("programmatic missing required did not fail closed: %#v", result)
	}
}

func TestCompositeRedactPreservesFragmentAndRequiredFindings(t *testing.T) {
	result := safeRunComposite(compositeRequest{
		ProtocolVersion: compositeProtocolVersion, Operation: "redact", RedactPercent: 75,
		Redaction: compositeFindingInput{
			RuleID: "primary", LineBase64: b64("line secret"), MatchBase64: b64("match secret"),
			SecretBase64: b64("secret"),
			Fragment: &directFragmentSnapshot{
				RawBase64: b64("raw secret"), BytesBase64: "", FileBase64: b64("fragment.go"),
				WindowsFileBase64: b64(`C:\fragment.go`), SymlinkFileBase64: b64("link"),
				CommitBase64: b64("commit"), StartLine: 41, Inherited: true,
			},
			RequiredFindings: []directRequiredFinding{{
				RuleID: "required", StartLine: 2, EndLine: 3, StartColumn: 4, EndColumn: 9,
				LineBase64: b64("required line"), MatchBase64: b64("required match"), SecretBase64: b64("required secret"),
			}},
		},
	})
	if result.Error != nil || result.Original == nil || result.Redacted == nil {
		t.Fatalf("full-state redaction failed: %#v", result)
	}
	if result.Redacted.Fragment == nil || result.Redacted.Fragment.RawBase64 != b64("raw secret") ||
		result.Redacted.Fragment.BytesBase64 != "" || result.Redacted.Fragment.StartLine != 41 ||
		!result.Redacted.Fragment.Inherited || len(result.Redacted.RequiredFindings) != 1 ||
		result.Redacted.RequiredFindings[0] != result.Original.RequiredFindings[0] ||
		result.Redacted.SecretBase64 != b64("se...") {
		t.Fatalf("fragment/required invariants changed: %#v", result)
	}
}

func TestAllowlistProtocolDirectMethodsPreserveObservablePayloads(t *testing.T) {
	validated := safeRunAllowlist(allowlistRequest{
		ProtocolVersion: allowlistProtocolVersion,
		ID:              "validated-commit",
		Operation:       "method",
		Method:          "commit",
		Validate:        true,
		Allowlist: allowlistInput{
			CommitsBase64: []string{base64.StdEncoding.EncodeToString([]byte(" CommitA "))},
		},
		InputBase64: base64.StdEncoding.EncodeToString([]byte("COMMITA")),
	})
	if validated.Error != nil || validated.Validation == nil || !validated.Validation.Success ||
		validated.MethodResult == nil || !validated.MethodResult.Allowed ||
		validated.MethodResult.MatchedValueBase64 != "" || validated.Normalized == nil ||
		strings.Join(validated.Normalized.Commits, ",") != "commita" {
		t.Fatalf("validated commit behavior changed: %#v", validated)
	}

	unvalidated := safeRunAllowlist(allowlistRequest{
		ProtocolVersion: allowlistProtocolVersion,
		ID:              "unvalidated-commit",
		Operation:       "method",
		Method:          "commit",
		Allowlist: allowlistInput{
			CommitsBase64: []string{base64.StdEncoding.EncodeToString([]byte("CommitA"))},
		},
		InputBase64: base64.StdEncoding.EncodeToString([]byte("CommitA")),
	})
	if unvalidated.Error != nil || unvalidated.MethodResult == nil || !unvalidated.MethodResult.Allowed ||
		unvalidated.MethodResult.MatchedValueBase64 != base64.StdEncoding.EncodeToString([]byte("CommitA")) {
		t.Fatalf("unvalidated commit payload changed: %#v", unvalidated)
	}

	nilReceiver := safeRunAllowlist(allowlistRequest{
		ProtocolVersion: allowlistProtocolVersion,
		ID:              "nil-stopword",
		Operation:       "method",
		Method:          "stopword",
		NilAllowlist:    true,
		InputBase64:     base64.StdEncoding.EncodeToString([]byte{0xff, 'A'}),
	})
	if nilReceiver.Error != nil || nilReceiver.MethodResult == nil || nilReceiver.MethodResult.Allowed ||
		nilReceiver.InputSHA256 == "" {
		t.Fatalf("nil receiver or arbitrary bytes changed: %#v", nilReceiver)
	}
}

func TestAllowlistProtocolDetectorLoadsPinnedFixture(t *testing.T) {
	result := safeRunAllowlist(allowlistRequest{
		ProtocolVersion: allowlistProtocolVersion,
		ID:              "fixture",
		Operation:       "detect",
		ConfigFixture:   "valid/allowlist_rule_regex.toml",
		Fragment: requestFragment{
			ContentBase64: base64.StdEncoding.EncodeToString([]byte(`awsToken := \"AKIA` + `LALEMEL33243OLIA\"`)),
			FileBase64:    base64.StdEncoding.EncodeToString([]byte("tmp.go")),
		},
		Options: requestOptions{},
	})
	if result.Error != nil || result.ConfigSHA256 == "" || result.InputSHA256 == "" ||
		result.TotalBytes == 0 || result.Findings == nil || len(result.Findings) != 0 {
		t.Fatalf("fixture detector behavior changed: %#v", result)
	}
}

func TestAllowlistProtocolRejectsWrongVersionAndTraversal(t *testing.T) {
	wrong := safeRunAllowlist(allowlistRequest{ProtocolVersion: allowlistProtocolVersion + 1})
	if wrong.Error == nil || wrong.Error.Class != "protocol" || wrong.Findings == nil {
		t.Fatalf("wrong allowlist protocol accepted: %#v", wrong)
	}
	traversal := safeRunAllowlist(allowlistRequest{
		ProtocolVersion: allowlistProtocolVersion,
		Operation:       "detect",
		ConfigFixture:   "../simple.toml",
		Fragment:        requestFragment{ContentBase64: ""},
	})
	if traversal.Error == nil || traversal.Error.Class != "config" ||
		!strings.Contains(traversal.Error.Message, "must stay within") {
		t.Fatalf("fixture traversal accepted: %#v", traversal)
	}
}

func TestSessionProtocolNormalizesIgnoreAndAppliesPrecedence(t *testing.T) {
	baseline := report.Finding{RuleID: "rule", Description: "description", StartLine: 7, EndLine: 7,
		StartColumn: 2, EndColumn: 8, Match: "MATCH", Secret: "secret", File: "base.txt",
		Commit: "base-commit", Entropy: 3.25, Author: "author", Email: "email", Date: "date", Message: "message"}
	baselineJSON, err := json.Marshal([]report.Finding{baseline})
	if err != nil {
		t.Fatal(err)
	}
	input := func(file, commit string, line int) compositeFindingInput {
		return compositeFindingInput{
			RuleID: "rule", DescriptionBase64: b64("description"), StartLine: line, EndLine: line,
			StartColumn: 2, EndColumn: 8, LineBase64: b64("line"), MatchBase64: b64("MATCH"),
			SecretBase64: b64("secret"), FileBase64: b64(file), CommitBase64: b64(commit),
			EntropyBits: math.Float32bits(3.25), AuthorBase64: b64("author"), EmailBase64: b64("email"),
			DateBase64: b64("date"), MessageBase64: b64("message"), TagsBase64: []string{},
			FingerprintBase64: b64("stale-input-fingerprint"),
		}
	}
	result := safeRunSession(sessionRequest{
		ProtocolVersion: sessionProtocolVersion, ID: "precedence", Operation: "session",
		IgnoreFile:   &sessionFileInput{Name: ".gitleaksignore", ContentBase64: b64("  foo\\bar.txt:rule:7  \n# comment\ncommit-x:zip\\inner.txt:rule:9\ninvalid\nfoo/bar.txt:rule:7\n")},
		BaselineFile: &sessionFileInput{Name: "baseline.json", ContentBase64: base64.StdEncoding.EncodeToString(baselineJSON)},
		Findings: []compositeFindingInput{
			input("foo/bar.txt", "base-commit", 7),
			input("zip/inner.txt", "commit-x", 9),
			input("base.txt", "base-commit", 7),
			input("accepted.txt", "", 3),
		},
	})
	if result.Error != nil {
		t.Fatalf("session failed: %#v", result)
	}
	if result.Ignore.UniqueCount != 3 || len(result.Baseline.Findings) != 1 || len(result.CollectedFindings) != 1 {
		t.Fatalf("session projection changed: %#v", result)
	}
	wantDispositions := []string{"ignored-global", "ignored-commit", "ignored-baseline", "accepted"}
	for index, want := range wantDispositions {
		if result.Decisions[index].Disposition != want {
			t.Fatalf("decision %d = %q, want %q", index, result.Decisions[index].Disposition, want)
		}
	}
	if result.InputFindings[3].FingerprintBase64 != b64("stale-input-fingerprint") ||
		result.CollectedFindings[0].FingerprintBase64 != b64("accepted.txt:rule:3") {
		t.Fatalf("fingerprint mutation boundary changed: %#v", result)
	}
	entries := make([]string, len(result.Ignore.EntriesBase64))
	for index, encoded := range result.Ignore.EntriesBase64 {
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		entries[index] = string(raw)
	}
	if strings.Join(entries, "|") != "commit-x:zip/inner.txt:rule:9|foo/bar.txt:rule:7|invalid" {
		t.Fatalf("normalized ignore keys changed: %#v", entries)
	}
}

func TestSessionProtocolPreservesDuplicatesOrderAndCompleteShape(t *testing.T) {
	input := func(rule string, line int) compositeFindingInput {
		return compositeFindingInput{
			RuleID: rule, DescriptionBase64: b64("description"), StartLine: line, EndLine: line,
			StartColumn: 1, EndColumn: 4, LineBase64: b64("line"), MatchBase64: b64("match"),
			SecretBase64: b64("secret"), FileBase64: b64("file"), SymlinkFileBase64: b64("symlink"),
			CommitBase64: b64("commit"), LinkBase64: b64("link"), EntropyBits: math.Float32bits(1.5),
			AuthorBase64: b64("author"), EmailBase64: b64("email"), DateBase64: b64("date"),
			MessageBase64: b64("message"), TagsBase64: []string{b64("tag")}, FingerprintBase64: b64("old"),
			Fragment: &directFragmentSnapshot{RawBase64: b64("raw"), BytesBase64: b64("bytes"), FileBase64: b64("fragment-file"),
				WindowsFileBase64: b64(`C:\fragment-file`), SymlinkFileBase64: b64("fragment-link"),
				CommitBase64: b64("fragment-commit"), StartLine: 41, Inherited: true},
			RequiredFindings: []directRequiredFinding{{RuleID: "required", StartLine: 2, EndLine: 2,
				StartColumn: 3, EndColumn: 6, LineBase64: b64("required-line"), MatchBase64: b64("required-match"), SecretBase64: b64("required-secret")}},
		}
	}
	a := input("z-rule", 9)
	b := input("a-rule", 1)
	result := safeRunSession(sessionRequest{ProtocolVersion: sessionProtocolVersion, ID: "order", Operation: "session",
		Findings: []compositeFindingInput{a, b, b}})
	if result.Error != nil || len(result.CollectedFindings) != 3 || len(result.CanonicalFindings) != 3 {
		t.Fatalf("session collection failed: %#v", result)
	}
	if result.CollectedFindings[0].RuleID != "z-rule" || result.CollectedFindings[1].RuleID != "a-rule" ||
		result.CollectedFindings[2].RuleID != "a-rule" || result.CanonicalFindings[0].RuleID != "a-rule" ||
		!reflect.DeepEqual(result.CanonicalFindings[1], result.CanonicalFindings[0]) {
		t.Fatalf("order or duplicates changed: %#v", result)
	}
	encoded, err := json.Marshal(result.CollectedFindings[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"fragment":`, `"required_findings":`, `"fingerprint_base64":`, `"tags_base64":`} {
		if !bytes.Contains(encoded, []byte(field)) {
			t.Fatalf("complete finding field %s missing from %s", field, encoded)
		}
	}
}

func TestSessionProtocolClassifiesBaselineErrorsAndVersions(t *testing.T) {
	ignoreMissing := safeRunSession(sessionRequest{ProtocolVersion: sessionProtocolVersion, Operation: "session",
		IgnoreFile: &sessionFileInput{Name: ".gitleaksignore", Missing: true}})
	if ignoreMissing.Error == nil || ignoreMissing.Error.Class != "ignore-open" || ignoreMissing.Error.Message != "could not open .gitleaksignore" {
		t.Fatalf("ignore open class changed: %#v", ignoreMissing)
	}
	format := safeRunSession(sessionRequest{ProtocolVersion: sessionProtocolVersion, Operation: "session",
		BaselineFile: &sessionFileInput{Name: "baseline.csv", ContentBase64: b64("not json")}})
	if format.Error == nil || format.Error.Class != "baseline-format" || format.Error.Message != "the format of the file baseline.csv is not supported" {
		t.Fatalf("baseline format class changed: %#v", format)
	}
	missing := safeRunSession(sessionRequest{ProtocolVersion: sessionProtocolVersion, Operation: "session",
		BaselineFile: &sessionFileInput{Name: "notfound.json", Missing: true}})
	if missing.Error == nil || missing.Error.Class != "baseline-open" || missing.Error.Message != "could not open notfound.json" {
		t.Fatalf("baseline open class changed: %#v", missing)
	}
	wrong := safeRunSession(sessionRequest{ProtocolVersion: sessionProtocolVersion + 1, Operation: "session"})
	if wrong.Error == nil || wrong.Error.Class != "protocol" || wrong.CollectedFindings == nil {
		t.Fatalf("wrong session protocol accepted: %#v", wrong)
	}
}

func decoderSyntheticSecret() string {
	return strings.Join([]string{
		"secret=",
		"ZGVjb2RlZC1zZWNyZXQtdmFsdWU=",
	}, "")
}

func TestDecoderProtocolExposesPassAndSegmentMetadata(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte(decoderSyntheticSecret()))
	result := safeRunDecoder(decoderRequest{
		ProtocolVersion: decoderProtocolVersion,
		ID:              "metadata",
		BehaviorIDs:     []string{"DEC-007", "DEC-008"},
		Operation:       "decode",
		InputsBase64:    []string{encoded, encoded},
		PassLimit:       8,
		ProbeRanges:     [][2]int{{0, 6}},
	})
	if result.Error != nil || result.OracleMode != "decoder" || len(result.Runs) != 2 {
		t.Fatalf("unexpected decoder result: %#v", result)
	}
	for _, run := range result.Runs {
		if !run.Terminated || len(run.Passes) < 2 || run.FullDecodeBase64 != base64.StdEncoding.EncodeToString([]byte("secret=decoded-secret-value")) {
			t.Fatalf("full decode or terminal pass changed: %#v", run)
		}
		first := run.Passes[0]
		if len(first.Segments) != 1 || len(first.Probes) == 0 || first.CurrentLineBase64 == "" {
			t.Fatalf("pass metadata missing: %#v", first)
		}
		segment := first.Segments[0]
		if segment.EncodingMask != 8 || strings.Join(segment.EncodingKinds, ",") != "base64" ||
			segment.Depth != 1 || segment.Original != segment.Encoded || segment.DecodedValueBase64 == "" ||
			segment.PredecessorIndices == nil {
			t.Fatalf("segment projection changed: %#v", segment)
		}
	}
}

func TestDecoderProtocolDetectUsesCompleteFindingProjection(t *testing.T) {
	configBytes := []byte("[[rules]]\nid = \"decoded\"\nregex = \"secret=(decoded-secret-value)\"\nsecretGroup = 1\n")
	result := safeRunDecoder(decoderRequest{
		ProtocolVersion: decoderProtocolVersion,
		ID:              "detect",
		Operation:       "detect",
		ConfigBase64:    base64.StdEncoding.EncodeToString(configBytes),
		Fragment: requestFragment{
			ContentBase64: base64.StdEncoding.EncodeToString([]byte(decoderSyntheticSecret())),
			FileBase64:    base64.StdEncoding.EncodeToString([]byte("tmp.go")),
		},
		Options: requestOptions{MaxDecodeDepth: 1},
	})
	if result.Error != nil || len(result.Findings) != 1 || result.ConfigSHA256 == "" || result.TotalBytes == 0 {
		t.Fatalf("unexpected decoded detector result: %#v", result)
	}
	finding := result.Findings[0]
	if finding.RuleID != "decoded" || finding.Fragment != nil || finding.RequiredFindings == nil ||
		strings.Join(finding.TagsBase64, ",") != strings.Join(b64Slice([]string{"decoded:base64", "decode-depth:1"}), ",") {
		t.Fatalf("complete decoded finding changed: %#v", finding)
	}
	encoded, err := json.Marshal(finding)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"fragment":null`, `"required_findings":[]`, `"entropy_bits":`} {
		if !bytes.Contains(encoded, []byte(field)) {
			t.Fatalf("finding field %s missing from %s", field, encoded)
		}
	}
}

func TestDecoderProtocolExposesCacheScopeAndPerPassSnapshots(t *testing.T) {
	input := base64.StdEncoding.EncodeToString([]byte("dGhpcy1pcy0xMjM0"))
	shared := safeRunDecoder(decoderRequest{
		ProtocolVersion: decoderProtocolVersion,
		Operation:       "decode",
		InputsBase64:    []string{input, input},
		DecoderScope:    "shared",
	})
	if shared.Error != nil || len(shared.Runs) != 2 || len(shared.Runs[0].Passes) != 2 {
		t.Fatalf("unexpected shared-cache result: %#v", shared)
	}
	entry := decoderCacheEntry{
		EncodedBase64: base64.StdEncoding.EncodeToString([]byte("dGhpcy1pcy0xMjM0")),
		DecodedBase64: base64.StdEncoding.EncodeToString([]byte("this-is-1234")),
	}
	if len(shared.Runs[0].Passes[0].CacheBefore) != 0 ||
		len(shared.Runs[0].Passes[0].CacheAfter) != 1 || shared.Runs[0].Passes[0].CacheAfter[0] != entry ||
		len(shared.Runs[1].CacheBefore) != 1 || shared.Runs[1].CacheBefore[0] != entry {
		t.Fatalf("shared per-pass cache snapshots changed: %#v", shared.Runs)
	}
	isolated := safeRunDecoder(decoderRequest{
		ProtocolVersion: decoderProtocolVersion,
		Operation:       "decode",
		InputsBase64:    []string{input, input},
		DecoderScope:    "isolated",
	})
	if isolated.Error != nil || len(isolated.Runs) != 2 ||
		len(isolated.Runs[0].CacheBefore) != 0 || len(isolated.Runs[1].CacheBefore) != 0 {
		t.Fatalf("isolated Decoder cache leaked: %#v", isolated)
	}
}

func TestDecoderProtocolFreezesNegativeDepthAdapterAndRepeatRuns(t *testing.T) {
	configBytes := []byte("[[rules]]\nid = \"raw\"\nregex = \"secret\"\n")
	request := decoderRequest{
		ProtocolVersion: decoderProtocolVersion,
		Operation:       "detect",
		ConfigBase64:    base64.StdEncoding.EncodeToString(configBytes),
		Fragment: requestFragment{
			ContentBase64: base64.StdEncoding.EncodeToString([]byte("secret")),
		},
		Options:           requestOptions{MaxDecodeDepth: -1},
		DetectRepeatCount: 3,
	}
	result := safeRunDecoder(request)
	if result.Error != nil || result.RequestedMaxDecodeDepth != -1 || result.RustAdapterMaxDecodeDepth != 0 ||
		len(result.Findings) != 1 || len(result.FindingRuns) != 3 || result.TotalBytes != 18 {
		t.Fatalf("negative depth or repeat projection changed: %#v", result)
	}
	want, err := json.Marshal(result.FindingRuns[0])
	if err != nil {
		t.Fatal(err)
	}
	for index, run := range result.FindingRuns[1:] {
		got, err := json.Marshal(run)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("finding run %d diverged: %s != %s", index+1, got, want)
		}
	}
}

func TestDecoderProtocolPreservesGoBase64TrailingBitPermissiveness(t *testing.T) {
	canonical := "dGhpcy1pcy0xMjM0NQ=="
	noncanonical := "dGhpcy1pcy0xMjM0NR=="
	result := safeRunDecoder(decoderRequest{
		ProtocolVersion: decoderProtocolVersion,
		ID:              "trailing-bits",
		Operation:       "decode",
		InputsBase64: []string{
			base64.StdEncoding.EncodeToString([]byte(canonical)),
			base64.StdEncoding.EncodeToString([]byte(noncanonical)),
		},
	})
	if result.Error != nil || len(result.Runs) != 2 {
		t.Fatalf("unexpected trailing-bit result: %#v", result)
	}
	expected := base64.StdEncoding.EncodeToString([]byte("this-is-12345"))
	for _, run := range result.Runs {
		if run.FullDecodeBase64 != expected || len(run.Passes[0].Segments) != 1 {
			t.Fatalf("Go trailing-bit permissiveness changed: %#v", run)
		}
	}
}

func TestDecoderProtocolRejectsWrongVersionAndTraversal(t *testing.T) {
	wrong := safeRunDecoder(decoderRequest{ProtocolVersion: decoderProtocolVersion + 1})
	if wrong.Error == nil || wrong.Error.Class != "protocol" || wrong.Runs == nil || wrong.Findings == nil {
		t.Fatalf("wrong decoder protocol accepted: %#v", wrong)
	}
	traversal := safeRunDecoder(decoderRequest{
		ProtocolVersion: decoderProtocolVersion,
		Operation:       "detect",
		ConfigFixture:   "../encoded.toml",
		Fragment:        requestFragment{ContentBase64: ""},
	})
	if traversal.Error == nil || traversal.Error.Class != "config" || !strings.Contains(traversal.Error.Message, "must stay within") {
		t.Fatalf("decoder fixture traversal accepted: %#v", traversal)
	}
	wrongTransform := safeRunDecoder(decoderRequest{
		ProtocolVersion: decoderProtocolVersion,
		Operation:       "decode",
		InputsBase64:    []string{base64.StdEncoding.EncodeToString([]byte("not escaped"))},
		SourceBase64:    base64.StdEncoding.EncodeToString([]byte("source bytes")),
		SourceTransform: "path-escape",
	})
	if wrongTransform.Error == nil || wrongTransform.Error.Class != "request" ||
		!strings.Contains(wrongTransform.Error.Message, "source transformation") {
		t.Fatalf("substituted source transformation accepted: %#v", wrongTransform)
	}
}

func TestDirectDetectorEntropyThresholdOutcomeSet(t *testing.T) {
	const iterations = 100_000
	const thresholdBits = uint64(0x4008d443070eac15)
	const acceptedEntropyBits = uint32(0x4046a218)

	var secret strings.Builder
	for index := 0; index < 10; index++ {
		secret.WriteString(strings.Repeat(string(rune('a'+index)), index+1))
	}
	if secret.Len() != 55 {
		t.Fatalf("entropy envelope secret length changed: %d", secret.Len())
	}

	cfg := config.Config{
		Rules: map[string]config.Rule{
			"entropy-envelope": {
				RuleID:  "entropy-envelope",
				Regex:   gitleaksregexp.MustCompile(`([a-j]{55})`),
				Entropy: math.Float64frombits(thresholdBits),
			},
		},
		Keywords: map[string]struct{}{},
	}
	detector := detect.NewDetector(cfg)
	seenRejected := false
	seenAccepted := false
	for index := 0; index < iterations; index++ {
		findings := detector.DetectString(secret.String())
		switch len(findings) {
		case 0:
			seenRejected = true
		case 1:
			seenAccepted = true
			if bits := math.Float32bits(findings[0].Entropy); bits != acceptedEntropyBits {
				t.Fatalf("accepted entropy bits changed: got %#08x, want %#08x", bits, acceptedEntropyBits)
			}
		default:
			t.Fatalf("entropy envelope produced %d findings", len(findings))
		}
	}
	if !seenRejected || !seenAccepted {
		t.Fatalf("entropy envelope outcome set incomplete after %d scans: rejected=%t accepted=%t",
			iterations, seenRejected, seenAccepted)
	}
}

func TestGoJSONReplacesEachInvalidByte(t *testing.T) {
	finding := report.Finding{Match: string([]byte{'m', 0xff, 0x80}), Tags: []string{}}
	encoded, err := json.Marshal(finding)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"Match":"m\ufffd\ufffd"`) {
		t.Fatalf("Go JSON invalid-UTF-8 behavior changed: %s", encoded)
	}
}

func TestFirstDifferenceIsReadable(t *testing.T) {
	err := firstDifference([]byte("one\ntwo\n"), []byte("one\nthree\n"))
	if err == nil || !strings.Contains(err.Error(), "line 2") ||
		!strings.Contains(err.Error(), "expected: two") ||
		!strings.Contains(err.Error(), "actual:   three") {
		t.Fatalf("unexpected difference: %v", err)
	}
}

func TestConfigOraclePreservesDuplicateOrderAndCanonicalizesSets(t *testing.T) {
	raw := `
TiTlE = "case insensitive"
unknownField = "ignored"

[[rules]]
ID = "duplicate"
REGEX = "first"
KEYWORDS = ["AWS"]
[[rules.ALLOWLISTS]]
COMMITS = [" B ", "a", "b"]
STOPWORDS = ["Z", "z", "a"]

[[rules]]
id = "duplicate"
regex = "second"
keywords = ["CMS"]

[[rules]]
id = "sets"
regex = "sets"
[[rules.allowlists]]
commits = [" B ", "a", "b"]
stopWords = ["Z", "z", "a"]
`
	result := safeRunConfig(configRequest{
		ProtocolVersion: protocolVersion,
		ID:              "duplicates",
		Source: configSource{
			Kind: "inline", ConfigBase64: base64.StdEncoding.EncodeToString([]byte(raw)),
		},
	})
	if result.Error != nil {
		t.Fatal(result.Error)
	}
	if result.Effective == nil {
		t.Fatal("missing effective config")
	}
	config := result.Effective
	if config.Title != "case insensitive" || len(config.OrderedRuleIDs) != 3 ||
		config.OrderedRuleIDs[0] != "duplicate" || config.OrderedRuleIDs[1] != "duplicate" {
		t.Fatalf("raw casing or ordered duplicates changed: %#v", config)
	}
	if len(config.DuplicateRuleIDs) != 1 || config.DuplicateRuleIDs[0].Count != 2 ||
		len(config.Rules) != 2 || value(config.Rules[0].Regex) != "second" {
		t.Fatalf("duplicate bookkeeping or last-write lookup changed: %#v", config)
	}
	if len(config.Rules[0].Allowlists) != 0 {
		t.Fatalf("overwritten rule retained the first allowlist: %#v", config.Rules[0])
	}
	set := config.Rules[1].Allowlists[0]
	if strings.Join(set.Commits, ",") != "a,b" || strings.Join(set.StopWords, ",") != "a,z" {
		t.Fatalf("set-like allowlist values were not canonical: %#v", set)
	}
	if len(config.NormalizedKeys) != 2 || config.NormalizedKeys[0] != "aws" || config.NormalizedKeys[1] != "cms" {
		t.Fatalf("global keywords no longer retain overwritten rules: %#v", config.NormalizedKeys)
	}
}

func TestConfigOracleOriginControlsEffectivePath(t *testing.T) {
	raw := []byte("[[rules]]\nid = \"a\"\nregex = \"a\"\n")
	result := safeRunConfig(configRequest{
		ProtocolVersion: protocolVersion,
		ID:              "origin",
		Source: configSource{
			Kind: "origin", Origin: "virtual/config.toml",
			ConfigBase64: base64.StdEncoding.EncodeToString(raw),
		},
	})
	if result.Error != nil || result.Effective == nil {
		t.Fatalf("origin config failed: %#v", result.Error)
	}
	if result.Effective.Path != "virtual/config.toml" {
		t.Fatalf("origin path not observed: %q", result.Effective.Path)
	}
}

func TestConfigOracleClassifiesTranslationErrors(t *testing.T) {
	raw := []byte("[[rules]]\nid = \"a\"\n")
	result := safeRunConfig(configRequest{
		ProtocolVersion: protocolVersion,
		ID:              "invalid",
		Source: configSource{
			Kind: "inline", ConfigBase64: base64.StdEncoding.EncodeToString(raw),
		},
	})
	if result.Error == nil || result.Error.Class != "rule" || result.Error.Stage != "translate" ||
		!strings.Contains(result.Error.Message, "both |regex| and |path| are empty") {
		t.Fatalf("unexpected structured error: %#v", result.Error)
	}
}

func TestConfigOneRejectsMultipleRecords(t *testing.T) {
	err := runConfigOne(strings.NewReader("{}\n{}\n"), "", "")
	if err == nil || !strings.Contains(err.Error(), "exactly one nonblank request, got 2") {
		t.Fatalf("multiple config records were not rejected: %v", err)
	}
}

func TestRegexOracleReportsAllCaptureSpans(t *testing.T) {
	result := safeRunRegex(regexRequest{
		ProtocolVersion: regexProtocolVersion,
		ID:              "captures",
		PatternBase64:   base64.StdEncoding.EncodeToString([]byte(`(?P<left>a)|(b)(c)?`)),
		InputBase64:     base64.StdEncoding.EncodeToString([]byte("a bc b")),
	})
	if result.Error != nil || !result.Compile.Success || result.Compile.CaptureCount != 3 {
		t.Fatalf("regex compile metadata changed: %#v", result)
	}
	if strings.Join(result.Compile.CaptureNames, ",") != ",left,," {
		t.Fatalf("capture names changed: %#v", result.Compile.CaptureNames)
	}
	want := []regexMatch{
		{Span: [2]int{0, 1}, Captures: [][2]int{{0, 1}, {0, 1}, {-1, -1}, {-1, -1}}},
		{Span: [2]int{2, 4}, Captures: [][2]int{{2, 4}, {-1, -1}, {2, 3}, {3, 4}}},
		{Span: [2]int{5, 6}, Captures: [][2]int{{5, 6}, {-1, -1}, {5, 6}, {-1, -1}}},
	}
	if !result.MatchExists || len(result.Matches) != len(want) {
		t.Fatalf("match enumeration changed: %#v", result.Matches)
	}
	for index := range want {
		if !equalRegexMatch(result.Matches[index], want[index]) {
			t.Fatalf("match %d changed: got %#v, want %#v", index, result.Matches[index], want[index])
		}
	}
}

func TestRegexOraclePreservesGoStringInvalidUTF8Semantics(t *testing.T) {
	result := safeRunRegex(regexRequest{
		ProtocolVersion: regexProtocolVersion,
		ID:              "invalid-utf8",
		PatternBase64:   base64.StdEncoding.EncodeToString([]byte(`.`)),
		InputBase64:     base64.StdEncoding.EncodeToString([]byte{0xff, 0x80, 'a'}),
	})
	want := [][2]int{{0, 1}, {1, 2}, {2, 3}}
	if result.Error != nil || len(result.Matches) != len(want) {
		t.Fatalf("invalid UTF-8 observation changed: %#v", result)
	}
	for index, span := range want {
		if result.Matches[index].Span != span {
			t.Fatalf("invalid UTF-8 span %d: got %v, want %v", index, result.Matches[index].Span, span)
		}
	}
}

func TestRegexOracleClassifiesCompileErrors(t *testing.T) {
	result := safeRunRegex(regexRequest{
		ProtocolVersion: regexProtocolVersion,
		ID:              "compile-error",
		PatternBase64:   base64.StdEncoding.EncodeToString([]byte(`a{1001}`)),
		InputBase64:     "",
	})
	if result.Error != nil || result.Compile.Success || result.Compile.ErrorCategory == "" ||
		!strings.Contains(result.Compile.ErrorMessage, "invalid repeat count") {
		t.Fatalf("compile error classification changed: %#v", result)
	}
}

func TestRegexOracleUsesGoEmptyMatchIteration(t *testing.T) {
	result := safeRunRegex(regexRequest{
		ProtocolVersion: regexProtocolVersion,
		ID:              "empty-matches",
		PatternBase64:   base64.StdEncoding.EncodeToString([]byte(`a*`)),
		InputBase64:     base64.StdEncoding.EncodeToString([]byte("ba")),
	})
	want := [][2]int{{0, 0}, {1, 2}}
	if len(result.Matches) != len(want) {
		t.Fatalf("empty match count changed: %#v", result.Matches)
	}
	for index, span := range want {
		if result.Matches[index].Span != span {
			t.Fatalf("empty match span %d: got %v, want %v", index, result.Matches[index].Span, span)
		}
	}
}

func TestRegexOracleAdvancesEmptyMatchesByUnicodeRune(t *testing.T) {
	result := safeRunRegex(regexRequest{
		ProtocolVersion: regexProtocolVersion,
		ID:              "unicode-empty-matches",
		PatternBase64:   base64.StdEncoding.EncodeToString([]byte(``)),
		InputBase64:     base64.StdEncoding.EncodeToString([]byte("é💩")),
	})
	want := [][2]int{{0, 0}, {2, 2}, {6, 6}}
	if len(result.Matches) != len(want) {
		t.Fatalf("Unicode empty match count changed: %#v", result.Matches)
	}
	for index, span := range want {
		if result.Matches[index].Span != span {
			t.Fatalf("Unicode empty match span %d: got %v, want %v", index, result.Matches[index].Span, span)
		}
	}
}

func TestRegexOracleMapsRuneErrorCapturesToOriginalInvalidBytes(t *testing.T) {
	result := safeRunRegex(regexRequest{
		ProtocolVersion: regexProtocolVersion,
		ID:              "invalid-byte-captures",
		PatternBase64:   base64.StdEncoding.EncodeToString([]byte(`(�)(.)?`)),
		InputBase64:     base64.StdEncoding.EncodeToString([]byte{0xff, 0xe2, 0x82}),
	})
	want := []regexMatch{
		{Span: [2]int{0, 2}, Captures: [][2]int{{0, 2}, {0, 1}, {1, 2}}},
		{Span: [2]int{2, 3}, Captures: [][2]int{{2, 3}, {2, 3}, {-1, -1}}},
	}
	if len(result.Matches) != len(want) {
		t.Fatalf("invalid-byte capture count changed: %#v", result.Matches)
	}
	for index := range want {
		if !equalRegexMatch(result.Matches[index], want[index]) {
			t.Fatalf("invalid-byte capture %d changed: got %#v, want %#v", index, result.Matches[index], want[index])
		}
	}
}

func TestRegexOracleFreezesLiteralBraceAndClassAlgebra(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		input   string
		span    [2]int
	}{
		{name: "malformed repetition is literal", pattern: `a{1,x}`, input: `a{1,x}`, span: [2]int{0, 6}},
		{name: "ampersands are class literals", pattern: `[a&&b]+`, input: `a&b`, span: [2]int{0, 3}},
		{name: "quoted syntax stays literal", pattern: `\Q[a&&b]{01}\E`, input: `[a&&b]{01}`, span: [2]int{0, 10}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := safeRunRegex(regexRequest{
				ProtocolVersion: regexProtocolVersion,
				ID:              test.name,
				PatternBase64:   base64.StdEncoding.EncodeToString([]byte(test.pattern)),
				InputBase64:     base64.StdEncoding.EncodeToString([]byte(test.input)),
			})
			if result.Error != nil || !result.Compile.Success || len(result.Matches) != 1 || result.Matches[0].Span != test.span {
				t.Fatalf("Go syntax behavior changed: %#v", result)
			}
		})
	}
}

func TestRegexOracleRejectsInvalidRequestData(t *testing.T) {
	wrongVersion := safeRunRegex(regexRequest{ProtocolVersion: regexProtocolVersion + 1})
	if wrongVersion.Error == nil || wrongVersion.Error.Class != "protocol" {
		t.Fatalf("wrong protocol accepted: %#v", wrongVersion)
	}
	badBase64 := safeRunRegex(regexRequest{ProtocolVersion: regexProtocolVersion, PatternBase64: "***"})
	if badBase64.Error == nil || badBase64.Error.Class != "request" {
		t.Fatalf("bad base64 accepted: %#v", badBase64)
	}
}

func TestReportProtocolFreezesJSONShapeBytesAndRedaction(t *testing.T) {
	percent := uint(75)
	input := reportTestFinding("secret")
	input.LineBase64 = b64("whole secret and secret")
	input.MatchBase64 = b64("match secret and secret")
	input.LinkBase64 = b64("https://example.test/link")
	result := safeRunReport(reportRequest{
		ProtocolVersion: reportProtocolVersion, ID: "json-redacted", Format: "json",
		Findings: []reportFindingInput{input}, RedactPercent: &percent,
	})
	if result.Error != nil || result.OutputBytes == 0 || len(result.RedactedFindings) != 1 {
		t.Fatalf("JSON report failed: %#v", result)
	}
	var decoded []map[string]any
	if err := json.Unmarshal(mustReportOutput(t, result), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 || decoded[0]["Secret"] != "se..." || decoded[0]["Match"] != "match se... and se..." ||
		decoded[0]["Link"] != "https://example.test/link" || decoded[0]["RuleID"] != "test-rule" {
		t.Fatalf("JSON shape/redaction changed: %#v", decoded)
	}
	if _, present := decoded[0]["Line"]; present {
		t.Fatalf("Line unexpectedly serialized: %#v", decoded[0])
	}
	if string(mustDecodeBase64(t, result.RedactedFindings[0].LineBase64)) != "whole se... and se..." {
		t.Fatalf("redacted line projection changed: %#v", result.RedactedFindings[0])
	}

	invalid := reportTestFinding(string(append([]byte{0xff, '<', '&'}, []byte("\u2028\u2029")...)))
	invalidResult := safeRunReport(reportRequest{ProtocolVersion: reportProtocolVersion, ID: "invalid", Format: "json", Findings: []reportFindingInput{invalid}})
	output := string(mustReportOutput(t, invalidResult))
	if invalidResult.Error != nil || !strings.Contains(output, `"Secret": "\ufffd\u003c\u0026\u2028\u2029"`) || !strings.Contains(output, `"Entropy": 3.5`) {
		t.Fatalf("JSON invalid-byte/HTML escaping changed: %q %#v", output, invalidResult.Error)
	}
}

func TestReportProtocolFreezesCSVLinkSelectionAndRawBytes(t *testing.T) {
	first := reportTestFinding("first")
	first.FileBase64 = base64.StdEncoding.EncodeToString([]byte{'a', ',', 'b', '\n', 0xff})
	second := reportTestFinding("second")
	second.LinkBase64 = b64("https://ignored.example")
	withoutLink := safeRunReport(reportRequest{ProtocolVersion: reportProtocolVersion, ID: "csv-no-link", Format: "csv", Findings: []reportFindingInput{first, second}})
	output := mustReportOutput(t, withoutLink)
	lines := bytes.Split(output, []byte{'\n'})
	if withoutLink.Error != nil || !bytes.HasSuffix(lines[0], []byte("Fingerprint,Tags")) || bytes.Contains(output, []byte("Link")) ||
		!bytes.Contains(output, []byte{0xff}) || bytes.Contains(output, []byte("ignored.example")) {
		t.Fatalf("CSV first-finding link/raw-byte behavior changed: %q %#v", output, withoutLink.Error)
	}
	first.LinkBase64 = b64("https://first.example")
	withLink := safeRunReport(reportRequest{ProtocolVersion: reportProtocolVersion, ID: "csv-link", Format: "csv", Findings: []reportFindingInput{first, second}})
	if withLink.Error != nil || !bytes.Contains(mustReportOutput(t, withLink), []byte("Fingerprint,Tags,Link\n")) ||
		!bytes.Contains(mustReportOutput(t, withLink), []byte("https://ignored.example")) {
		t.Fatalf("CSV link column changed: %#v", withLink)
	}
	leading := reportTestFinding("\u2003é💩")
	leading.RuleIDBase64 = b64("\u00a0leading")
	leading.FileBase64 = b64(`\.`)
	leading.MatchBase64 = b64(`prefix \. suffix`)
	leadingResult := safeRunReport(reportRequest{ProtocolVersion: reportProtocolVersion, ID: "csv-leading", Format: "csv", Findings: []reportFindingInput{leading}})
	leadingOutput := mustReportOutput(t, leadingResult)
	if leadingResult.Error != nil || !bytes.Contains(leadingOutput, []byte("\"\u00a0leading\",")) || !bytes.Contains(leadingOutput, []byte(`,"\.",`)) ||
		!bytes.Contains(leadingOutput, []byte("\"\u2003é💩\"")) {
		t.Fatalf("CSV Unicode/leading-space/backslash-dot quoting changed: %q", leadingOutput)
	}
	empty := safeRunReport(reportRequest{ProtocolVersion: reportProtocolVersion, ID: "csv-empty", Format: "csv"})
	if empty.Error != nil || empty.OutputBytes != 0 {
		t.Fatalf("empty CSV changed: %#v", empty)
	}
}

func TestReportProtocolFreezesJUnitAndSARIFInvalidText(t *testing.T) {
	finding := reportTestFinding(string(append([]byte{'s', 0xff, '<', '&'}, []byte("\u2028\u2029")...)))
	finding.DescriptionBase64 = base64.StdEncoding.EncodeToString([]byte{'b', 'a', 'd', 0x01, 0xff})
	finding.FileBase64 = base64.StdEncoding.EncodeToString([]byte{'f', 0xff, '<', '&'})
	junit := safeRunReport(reportRequest{ProtocolVersion: reportProtocolVersion, ID: "junit-invalid", Format: "junit", Findings: []reportFindingInput{finding}})
	junitOutput := mustReportOutput(t, junit)
	if junit.Error != nil || !bytes.Contains(junitOutput, []byte("bad��")) ||
		!bytes.Contains(junitOutput, []byte(`\u003c\u0026\u2028\u2029`)) || !bytes.Contains(junitOutput, []byte(`&#34;Entropy&#34;: 3.5`)) {
		t.Fatalf("JUnit invalid/control/float/escaping changed: %q %#v", junitOutput, junit.Error)
	}
	sarif := safeRunReport(reportRequest{
		ProtocolVersion: reportProtocolVersion, ID: "sarif-invalid", Format: "sarif", Findings: []reportFindingInput{finding},
		OrderedRules: []reportRuleInput{{IDBase64: b64("test-rule"), DescriptionBase64: b64("description")}},
	})
	sarifOutput := mustReportOutput(t, sarif)
	if sarif.Error != nil || !bytes.Contains(sarifOutput, []byte(`\ufffd\u003c\u0026`)) ||
		!bytes.Contains(sarifOutput, []byte(`\u2028\u2029`)) {
		t.Fatalf("SARIF invalid-byte message/snippet behavior changed: %q %#v", sarifOutput, sarif.Error)
	}
}

func TestReportProtocolFreezesSARIFRuleOrderAndSymlinkLocation(t *testing.T) {
	finding := reportTestFinding("secret")
	finding.FileBase64 = b64("real/path")
	finding.SymlinkFileBase64 = b64("link/path")
	result := safeRunReport(reportRequest{
		ProtocolVersion: reportProtocolVersion, ID: "sarif", Format: "sarif", Findings: []reportFindingInput{finding},
		OrderedRules: []reportRuleInput{{IDBase64: b64("z"), DescriptionBase64: b64("last")}, {IDBase64: b64("a"), DescriptionBase64: b64("first")}},
	})
	var document struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				Locations []struct {
					Physical struct {
						Artifact struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(mustReportOutput(t, result), &document); err != nil {
		t.Fatal(err)
	}
	if result.Error != nil || len(document.Runs) != 1 || len(document.Runs[0].Tool.Driver.Rules) != 2 ||
		document.Runs[0].Tool.Driver.Rules[0].ID != "z" || document.Runs[0].Tool.Driver.Rules[1].ID != "a" ||
		document.Runs[0].Results[0].Locations[0].Physical.Artifact.URI != "link/path" {
		t.Fatalf("SARIF ordering/location changed: %#v %#v", document, result.Error)
	}
}

func TestReportProtocolFreezesTemplateSecurityAndErrorBoundaries(t *testing.T) {
	for _, function := range []string{"env", "expandenv", "getHostByName"} {
		result := safeRunReport(reportRequest{
			ProtocolVersion: reportProtocolVersion, ID: function, Format: "template", TemplateMode: "validate",
			TemplateBase64: b64(fmt.Sprintf(`{{ %s "value" }}`, function)),
		})
		if result.Error == nil || result.Error.Class != "template-parse" || !strings.Contains(result.Error.Message, fmt.Sprintf("function %q not defined", function)) {
			t.Fatalf("dangerous template function %s accepted: %#v", function, result)
		}
	}
	allowed := safeRunReport(reportRequest{
		ProtocolVersion: reportProtocolVersion, ID: "allowed", Format: "template", Findings: []reportFindingInput{reportTestFinding("secret")},
		TemplateBase64: b64(`{{ upper (index . 0).RuleID }}|{{ quote (index . 0).Secret }}|{{ sha256sum "x" }}`),
	})
	if allowed.Error != nil || !strings.HasPrefix(string(mustReportOutput(t, allowed)), `TEST-RULE|"secret"|2d711642b726b044`) {
		t.Fatalf("safe template helpers changed: %q %#v", mustReportOutput(t, allowed), allowed.Error)
	}
	parseOnly := safeRunReport(reportRequest{ProtocolVersion: reportProtocolVersion, ID: "now", Format: "template", TemplateMode: "validate", TemplateBase64: b64(`{{ now }}`)})
	if parseOnly.Error != nil || parseOnly.OutputBytes != 0 {
		t.Fatalf("allowed nondeterministic helper no longer parses: %#v", parseOnly)
	}
	executeError := safeRunReport(reportRequest{
		ProtocolVersion: reportProtocolVersion, ID: "execute-error", Format: "template", Findings: []reportFindingInput{reportTestFinding("secret")},
		TemplateBase64: b64(`{{ index . 99 }}`),
	})
	if executeError.Error == nil || executeError.Error.Class != "template-execute" {
		t.Fatalf("template execution error changed: %#v", executeError)
	}
}

func TestReportProtocolClassifiesWriterFormatAndRequestErrors(t *testing.T) {
	zero := 0
	for _, format := range []string{"json", "csv", "junit", "sarif", "template"} {
		req := reportRequest{ProtocolVersion: reportProtocolVersion, ID: format, Format: format, Findings: []reportFindingInput{reportTestFinding("secret")}, FailAfterBytes: &zero}
		if format == "template" {
			req.TemplateBase64 = b64(`{{ (index . 0).Secret }}`)
		}
		result := safeRunReport(req)
		if result.Error == nil || result.Error.Class != "writer" {
			t.Fatalf("%s writer error changed: %#v", format, result)
		}
	}
	unknown := safeRunReport(reportRequest{ProtocolVersion: reportProtocolVersion, Format: "yaml"})
	wrong := safeRunReport(reportRequest{ProtocolVersion: reportProtocolVersion + 1, Format: "json"})
	bad := reportTestFinding("secret")
	bad.SecretBase64 = "***"
	badBase64 := safeRunReport(reportRequest{ProtocolVersion: reportProtocolVersion, Format: "json", Findings: []reportFindingInput{bad}})
	if unknown.Error == nil || unknown.Error.Class != "format" || wrong.Error == nil || wrong.Error.Class != "protocol" ||
		badBase64.Error == nil || badBase64.Error.Class != "request" {
		t.Fatalf("structured report errors changed: unknown=%#v wrong=%#v bad=%#v", unknown.Error, wrong.Error, badBase64.Error)
	}
}

func reportTestFinding(secret string) reportFindingInput {
	return reportFindingInput{
		RuleIDBase64: b64("test-rule"), DescriptionBase64: b64("Test Rule"), StartLine: 1, EndLine: 2,
		StartColumn: 3, EndColumn: 4, LineBase64: b64("line " + secret), MatchBase64: b64("match " + secret), SecretBase64: b64(secret),
		FileBase64: b64("auth.py"), CommitBase64: b64("abc123"), EntropyBits: math.Float32bits(3.5),
		AuthorBase64: b64("Alice"), EmailBase64: b64("alice@example.test"), DateBase64: b64("2026-08-22"),
		MessageBase64: b64("message"), TagsBase64: []string{b64("tag1"), b64("tag2")}, FingerprintBase64: b64("fingerprint"),
	}
}

func mustReportOutput(t *testing.T, result reportResponse) []byte {
	t.Helper()
	return mustDecodeBase64(t, result.OutputBase64)
}

func equalRegexMatch(left, right regexMatch) bool {
	if left.Span != right.Span || len(left.Captures) != len(right.Captures) {
		return false
	}
	for index := range left.Captures {
		if left.Captures[index] != right.Captures[index] {
			return false
		}
	}
	return true
}

func value(pointer *string) string {
	if pointer == nil {
		return ""
	}
	return *pointer
}
