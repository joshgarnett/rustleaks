package rustleaks

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// The shared binding cases in testdata/bindings. See its README for the
// format. The expected values are fixed; a failure is a bug in this package
// or the library.

type corpus struct {
	Cases []corpusCase `json:"cases"`
}

type corpusCase struct {
	Name   string       `json:"name"`
	Engine corpusEngine `json:"engine"`
	Scan   struct {
		Input segments `json:"input"`
		Path  *string  `json:"path"`
	} `json:"scan"`
	Expect struct {
		Error    *string           `json:"error"`
		Findings []expectedFinding `json:"findings"`
	} `json:"expect"`
}

type corpusEngine struct {
	Config            *string   `json:"config"`
	Rules             *[]string `json:"rules"`
	AllowComments     *bool     `json:"allow_comments"`
	DecodeDepth       *int      `json:"decode_depth"`
	MaxInputBytes     *uint64   `json:"max_input_bytes"`
	MaxFindingRecords *uint64   `json:"max_finding_records"`
}

type expectedFinding struct {
	RuleID      string    `json:"rule_id"`
	Secret      segments  `json:"secret"`
	Match       segments  `json:"match"`
	Line        *segments `json:"line"`
	StartLine   int       `json:"start_line"`
	EndLine     int       `json:"end_line"`
	StartColumn int       `json:"start_column"`
	EndColumn   int       `json:"end_column"`
	SecretRange *[2]int   `json:"secret_range"`
}

// segments is a list of JSON strings and {"hex": "..."} objects, joined.
type segments []byte

func (s *segments) UnmarshalJSON(data []byte) error {
	var parts []json.RawMessage
	if err := json.Unmarshal(data, &parts); err != nil {
		return err
	}
	var out []byte
	for _, part := range parts {
		var text string
		if err := json.Unmarshal(part, &text); err == nil {
			out = append(out, text...)
			continue
		}
		var object struct {
			Hex *string `json:"hex"`
		}
		if err := json.Unmarshal(part, &object); err != nil || object.Hex == nil {
			return fmt.Errorf("segment %s is neither a string nor a hex object", part)
		}
		decoded, err := hex.DecodeString(*object.Hex)
		if err != nil {
			return err
		}
		out = append(out, decoded...)
	}
	*s = out
	return nil
}

func loadCorpus(t *testing.T) (corpus, string) {
	t.Helper()
	path := repoFile(t, "testdata/bindings/cases.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cases corpus
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases.Cases) == 0 {
		t.Fatal("the corpus has no cases")
	}
	return cases, filepath.Dir(path)
}

func (c corpusEngine) options(t *testing.T, dir string) []Option {
	t.Helper()
	var opts []Option
	if c.Config != nil {
		config, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(*c.Config)))
		if err != nil {
			t.Fatal(err)
		}
		opts = append(opts, WithConfig(config))
	}
	if c.Rules != nil {
		opts = append(opts, WithRules(*c.Rules...))
	}
	if c.AllowComments != nil {
		opts = append(opts, WithAllowComments(*c.AllowComments))
	}
	if c.DecodeDepth != nil {
		opts = append(opts, WithDecodeDepth(*c.DecodeDepth))
	}
	if c.MaxInputBytes != nil {
		opts = append(opts, WithMaxInputBytes(*c.MaxInputBytes))
	}
	if c.MaxFindingRecords != nil {
		opts = append(opts, WithBudget(BudgetFindingRecords, *c.MaxFindingRecords))
	}
	return opts
}

func TestCorpus(t *testing.T) {
	cases, dir := loadCorpus(t)
	type built struct {
		engine *Engine
		err    error
	}
	engines := map[string]built{}
	t.Cleanup(func() {
		for _, b := range engines {
			if b.engine != nil {
				b.engine.Close()
			}
		}
	})
	names := map[string]bool{}
	for _, tc := range cases.Cases {
		if names[tc.Name] {
			t.Fatalf("case name %q is not unique", tc.Name)
		}
		names[tc.Name] = true
		t.Run(tc.Name, func(t *testing.T) {
			key, err := json.Marshal(tc.Engine)
			if err != nil {
				t.Fatal(err)
			}
			b, ok := engines[string(key)]
			if !ok {
				b.engine, b.err = New(tc.Engine.options(t, dir)...)
				engines[string(key)] = b
			}
			var opts []ScanOption
			path := ""
			if tc.Scan.Path != nil {
				path = *tc.Scan.Path
				opts = append(opts, WithPath(path))
			}
			want := ""
			if tc.Expect.Error != nil {
				want = *tc.Expect.Error
			}
			if b.err != nil {
				checkCorpusError(t, "New", b.err, want)
				return
			}
			input := []byte(tc.Scan.Input)
			fromBytes, errBytes := b.engine.ScanBytes(context.Background(), input, opts...)
			fromString, errString := b.engine.ScanString(context.Background(), string(input), opts...)
			for _, result := range []struct {
				method   string
				findings []Finding
				err      error
			}{{"ScanBytes", fromBytes, errBytes}, {"ScanString", fromString, errString}} {
				if want != "" {
					checkCorpusError(t, result.method, result.err, want)
					if result.findings != nil {
						t.Errorf("%s returned %d findings with its error", result.method, len(result.findings))
					}
					continue
				}
				if result.err != nil {
					t.Fatalf("%s: %v", result.method, result.err)
				}
				checkCorpusFindings(t, result.method, result.findings, tc.Expect.Findings, path)
			}
		})
	}
}

func checkCorpusError(t *testing.T, method string, err error, want string) {
	t.Helper()
	if want == "" {
		t.Fatalf("%s: unexpected error: %v", method, err)
	}
	if err == nil {
		t.Fatalf("%s: no error, want %s", method, want)
	}
	var config *ConfigError
	var incomplete *IncompleteError
	switch want {
	case "config":
		if !errors.As(err, &config) || config.Kind != KindConfig {
			t.Fatalf("%s: error %v, want a config error", method, err)
		}
	case "rule_selection":
		if !errors.As(err, &config) || config.Kind != KindRuleSelection {
			t.Fatalf("%s: error %v, want a rule selection error", method, err)
		}
	case "input_too_large":
		if !errors.Is(err, ErrInputTooLarge) {
			t.Fatalf("%s: error %v, want ErrInputTooLarge", method, err)
		}
	case "budget_exceeded":
		if !errors.As(err, &incomplete) || incomplete.Termination != TerminationBudget {
			t.Fatalf("%s: error %v, want a budget IncompleteError", method, err)
		}
	default:
		t.Fatalf("unknown expected error %q", want)
	}
}

func checkCorpusFindings(t *testing.T, method string, got []Finding, want []expectedFinding, path string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: %d findings %v, want %d", method, len(got), got, len(want))
	}
	for i, w := range want {
		g := got[i]
		check := func(field string, gotValue, wantValue any) {
			t.Helper()
			if gotValue != wantValue {
				t.Errorf("%s: finding %d %s = %#v, want %#v", method, i, field, gotValue, wantValue)
			}
		}
		check("RuleID", g.RuleID, w.RuleID)
		if !bytes.Equal([]byte(g.Secret), w.Secret) {
			t.Errorf("%s: finding %d Secret = %q, want %q", method, i, g.Secret, w.Secret)
		}
		if !bytes.Equal([]byte(g.Match), w.Match) {
			t.Errorf("%s: finding %d Match = %q, want %q", method, i, g.Match, w.Match)
		}
		if w.Line != nil && !bytes.Equal([]byte(g.Line), *w.Line) {
			t.Errorf("%s: finding %d Line = %q, want %q", method, i, g.Line, *w.Line)
		}
		check("StartLine", g.StartLine, w.StartLine)
		check("EndLine", g.EndLine, w.EndLine)
		check("StartColumn", g.StartColumn, w.StartColumn)
		check("EndColumn", g.EndColumn, w.EndColumn)
		if w.SecretRange == nil {
			check("SecretRange", g.SecretRange, Range{})
		} else {
			check("SecretRange", g.SecretRange, Range{Start: w.SecretRange[0], End: w.SecretRange[1], OK: true})
		}
		check("Path", g.Path, path)
	}
}
