package rustleaks

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sync"
	"testing"
)

// The findings that rustleaks-core reports for a fixed set of files, written
// at build time by //crates/rustleaks-eval:binding_reference. This test scans
// the same files through the package and requires the same findings in the
// same order. It compares two implementations; it stores no expected values.

type reference struct {
	Inputs []referenceInput `json:"inputs"`
}

type referenceInput struct {
	Path     string             `json:"path"`
	Variant  string             `json:"variant"`
	Findings []referenceFinding `json:"findings"`
}

type referenceFinding struct {
	RuleID      string   `json:"rule_id"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
	Secret      hexBytes `json:"secret"`
	Match       hexBytes `json:"match"`
	Line        hexBytes `json:"line"`
	StartLine   int      `json:"start_line"`
	EndLine     int      `json:"end_line"`
	StartColumn int      `json:"start_column"`
	EndColumn   int      `json:"end_column"`
	SecretRange *[2]int  `json:"secret_range"`
	MatchRange  *[2]int  `json:"match_range"`
	Entropy     float64  `json:"entropy"`
}

// hexBytes is a JSON string of hex digits.
type hexBytes []byte

func (h *hexBytes) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return err
	}
	decoded, err := hex.DecodeString(text)
	*h = decoded
	return err
}

// referenceContent returns the scanned form of a file, as the reference tool
// makes it.
func referenceContent(data []byte, variant string) ([]byte, error) {
	switch variant {
	case "file":
		return data, nil
	case "crlf":
		return bytes.ReplaceAll(data, []byte("\n"), []byte("\r\n")), nil
	case "no-final-newline":
		if !bytes.HasSuffix(data, []byte("\n")) {
			return nil, fmt.Errorf("no final line break to remove")
		}
		return data[:len(data)-1], nil
	}
	return nil, fmt.Errorf("unknown variant %q", variant)
}

func toRange(r *[2]int) Range {
	if r == nil {
		return Range{}
	}
	return Range{Start: r[0], End: r[1], OK: true}
}

// compareReference returns the differences between the package findings and
// the core findings of one input.
func compareReference(got []Finding, want []referenceFinding, path string) []string {
	var out []string
	if len(got) != len(want) {
		out = append(out, fmt.Sprintf("%d findings, core reported %d", len(got), len(want)))
	}
	for i := 0; i < len(got) && i < len(want); i++ {
		g, w := got[i], want[i]
		field := func(name string, gotValue, wantValue any) {
			if !reflect.DeepEqual(gotValue, wantValue) {
				out = append(out, fmt.Sprintf("finding %d %s = %#v, core %#v", i, name, gotValue, wantValue))
			}
		}
		field("RuleID", g.RuleID, w.RuleID)
		field("Description", g.Description, w.Description)
		field("Tags", append([]string{}, g.Tags...), append([]string{}, w.Tags...))
		field("Secret", []byte(g.Secret), []byte(w.Secret))
		field("Match", []byte(g.Match), []byte(w.Match))
		field("Line", []byte(g.Line), []byte(w.Line))
		field("StartLine", g.StartLine, w.StartLine)
		field("EndLine", g.EndLine, w.EndLine)
		field("StartColumn", g.StartColumn, w.StartColumn)
		field("EndColumn", g.EndColumn, w.EndColumn)
		field("SecretRange", g.SecretRange, toRange(w.SecretRange))
		field("MatchRange", g.MatchRange, toRange(w.MatchRange))
		field("Entropy", g.Entropy, w.Entropy)
		field("Path", g.Path, path)
		if len(out) > 0 {
			// Later findings usually differ for the same reason.
			break
		}
	}
	return out
}

func TestReferenceFindings(t *testing.T) {
	data, err := os.ReadFile(repoFile(t, "crates/rustleaks-eval/binding-reference.json"))
	if err != nil {
		t.Fatal(err)
	}
	var ref reference
	if err := json.Unmarshal(data, &ref); err != nil {
		t.Fatal(err)
	}
	if len(ref.Inputs) == 0 {
		t.Fatal("the reference has no inputs")
	}
	engine, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()

	files := map[string][]byte{}
	for _, input := range ref.Inputs {
		if _, ok := files[input.Path]; !ok {
			content, err := os.ReadFile(repoFile(t, input.Path))
			if err != nil {
				t.Fatal(err)
			}
			files[input.Path] = content
		}
	}

	differences := make([][]string, len(ref.Inputs))
	var wg sync.WaitGroup
	next := make(chan int)
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range next {
				input := ref.Inputs[index]
				content, err := referenceContent(files[input.Path], input.Variant)
				if err != nil {
					differences[index] = []string{err.Error()}
					continue
				}
				got, err := engine.ScanBytes(context.Background(), content, WithPath(input.Path))
				if err != nil {
					differences[index] = []string{err.Error()}
					continue
				}
				differences[index] = compareReference(got, input.Findings, input.Path)
			}
		}()
	}
	for index := range ref.Inputs {
		next <- index
	}
	close(next)
	wg.Wait()

	failed, findings, rules := 0, 0, map[string]bool{}
	for index, input := range ref.Inputs {
		findings += len(input.Findings)
		for _, finding := range input.Findings {
			rules[finding.RuleID] = true
		}
		if len(differences[index]) == 0 {
			continue
		}
		failed++
		if failed <= 10 {
			t.Errorf("%s (%s): %v", input.Path, input.Variant, differences[index])
		}
	}
	if failed > 0 {
		t.Fatalf("%d of %d inputs differ from core", failed, len(ref.Inputs))
	}
	t.Logf("%d inputs from %d files, %d findings, %d of %d rules", len(ref.Inputs), len(files), findings, len(rules), len(engine.Rules()))
	if findings == 0 {
		t.Fatal("the reference has no findings")
	}
}

func TestCompareReferenceReportsEachField(t *testing.T) {
	want := referenceFinding{
		RuleID: "rule", Description: "d", Tags: []string{"t"},
		Secret: hexBytes("s"), Match: hexBytes("m"), Line: hexBytes("l"),
		StartLine: 1, EndLine: 1, StartColumn: 2, EndColumn: 3,
		SecretRange: &[2]int{1, 2}, Entropy: 0.5,
	}
	same := Finding{
		RuleID: "rule", Description: "d", Tags: []string{"t"}, Secret: "s", Match: "m", Line: "l",
		StartLine: 1, EndLine: 1, StartColumn: 2, EndColumn: 3,
		SecretRange: Range{Start: 1, End: 2, OK: true}, Entropy: 0.5, Path: "p",
	}
	if diff := compareReference([]Finding{same}, []referenceFinding{want}, "p"); diff != nil {
		t.Fatalf("equal findings differ: %v", diff)
	}
	for name, change := range map[string]func(*Finding){
		"Tags":       func(f *Finding) { f.Tags = nil },
		"Secret":     func(f *Finding) { f.Secret = "x" },
		"Line":       func(f *Finding) { f.Line = "l\r" },
		"EndColumn":  func(f *Finding) { f.EndColumn = 4 },
		"MatchRange": func(f *Finding) { f.MatchRange = Range{OK: true} },
		"Entropy":    func(f *Finding) { f.Entropy = 0.25 },
		"Path":       func(f *Finding) { f.Path = "q" },
	} {
		changed := same
		change(&changed)
		if compareReference([]Finding{changed}, []referenceFinding{want}, "p") == nil {
			t.Errorf("a changed %s is not reported", name)
		}
	}
	if compareReference(nil, []referenceFinding{want}, "p") == nil {
		t.Error("a missing finding is not reported")
	}
}
