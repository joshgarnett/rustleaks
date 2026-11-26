package rustleaks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// formatMarker is a synthetic secret. No printed or logged form of a
// finding, and no error, may contain it.
const formatMarker = "QZXWVUTSRQPO"

const formatConfig = `
[[rules]]
id = "synthetic-format"
description = "A synthetic secret for format tests"
regex = '''SYNTH-([A-Z]{12})'''
secretGroup = 1
keywords = ["synth-"]
`

func formatFindings(t *testing.T) []Finding {
	t.Helper()
	e := newEngine(t, WithConfig([]byte(formatConfig)))
	findings, err := e.ScanString(context.Background(), "token SYNTH-"+formatMarker+" end\n", WithPath("app.env"))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Secret != formatMarker {
		t.Fatalf("findings %v", findings)
	}
	return findings
}

func checkNoMarker(t *testing.T, name, text string) {
	t.Helper()
	if strings.Contains(text, formatMarker) {
		t.Errorf("%s holds the secret: %s", name, text)
	}
	if text == "" {
		t.Errorf("%s is empty", name)
	}
}

func TestFormattingLeavesOutTheSecret(t *testing.T) {
	findings := formatFindings(t)
	f := findings[0]
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d", "%10v"} {
		checkNoMarker(t, "Sprintf("+verb+", finding)", fmt.Sprintf(verb, f))
		checkNoMarker(t, "Sprintf("+verb+", &finding)", fmt.Sprintf(verb, &f))
		checkNoMarker(t, "Sprintf("+verb+", findings)", fmt.Sprintf(verb, findings))
	}
	checkNoMarker(t, "Sprint", fmt.Sprint(f, findings))
	checkNoMarker(t, "Sprintln", fmt.Sprintln(f))
	checkNoMarker(t, "map value", fmt.Sprintf("%v %+v", map[string]Finding{"k": f}, struct{ F Finding }{f}))

	if got, want := f.String(), "{RuleID:synthetic-format Path:app.env StartLine:1 EndLine:1 StartColumn:7 EndColumn:24}"; got != want {
		t.Errorf("String() = %s, want %s", got, want)
	}
	if got, want := fmt.Sprintf("%#v", f), `rustleaks.Finding{RuleID:"synthetic-format", Path:"app.env", StartLine:1, EndLine:1, StartColumn:7, EndColumn:24}`; got != want {
		t.Errorf("%%#v = %s, want %s", got, want)
	}

	for name, handler := range map[string]func(*bytes.Buffer) slog.Handler{
		"text": func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
		"json": func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
	} {
		var out bytes.Buffer
		logger := slog.New(handler(&out))
		logger.Info("found", "finding", f)
		logger.Info("found", slog.Any("finding", &f))
		checkNoMarker(t, "slog "+name, out.String())
		if !strings.Contains(out.String(), "synthetic-format") {
			t.Errorf("slog %s output has no rule ID: %s", name, out.String())
		}
	}
}

// TestCollectionsLeaveOutTheSecret logs and encodes findings the way a
// program logs a scan result: the slice that a scan returns, a map value
// and a struct field.
func TestCollectionsLeaveOutTheSecret(t *testing.T) {
	findings := formatFindings(t)
	type report struct {
		Name     string
		Findings []Finding
		First    Finding
		Pointer  *Finding
	}
	values := map[string]any{
		"slice":  findings,
		"map":    map[string]Finding{"first": findings[0]},
		"struct": report{Name: "scan", Findings: findings, First: findings[0], Pointer: &findings[0]},
		"nested": map[string][]Finding{"app.env": findings},
	}
	for name, value := range values {
		for handlerName, handler := range map[string]func(*bytes.Buffer) slog.Handler{
			"text": func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
			"json": func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
		} {
			var out bytes.Buffer
			slog.New(handler(&out)).Info("found", "findings", value)
			checkNoMarker(t, "slog "+handlerName+" "+name, out.String())
			if !strings.Contains(out.String(), "synthetic-format") {
				t.Errorf("slog %s %s has no rule ID: %s", handlerName, name, out.String())
			}
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		checkNoMarker(t, "json.Marshal "+name, string(encoded))
	}

	encoded, err := json.Marshal(findings)
	if err != nil {
		t.Fatal(err)
	}
	var decoded []map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"Secret", "Match", "Line"} {
		if _, ok := decoded[0][field]; ok {
			t.Errorf("JSON has %s", field)
		}
	}
	for _, field := range []string{"RuleID", "Description", "Tags", "StartLine", "EndLine", "StartColumn", "EndColumn", "SecretRange", "MatchRange", "Entropy", "Path"} {
		if _, ok := decoded[0][field]; !ok {
			t.Errorf("JSON has no %s: %s", field, encoded)
		}
	}
}

// TestUnexportedFieldShowsTheSecret pins the limit that the docs state: fmt
// cannot call the methods of a Finding in an unexported struct field, so it
// prints the fields, secret included. If this test fails, fmt changed and
// the docs can drop the warning.
func TestUnexportedFieldShowsTheSecret(t *testing.T) {
	findings := formatFindings(t)
	value := struct{ finding Finding }{findings[0]}
	if text := fmt.Sprintf("%+v", value); !strings.Contains(text, formatMarker) {
		t.Errorf("fmt no longer prints an unexported Finding field: %s", text)
	}
	// encoding/json skips unexported fields.
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), formatMarker) {
		t.Errorf("json.Marshal wrote an unexported field: %s", encoded)
	}
}

func TestErrorsLeaveOutTheInput(t *testing.T) {
	ctx := context.Background()
	input := "SYNTH-" + formatMarker + "\n"
	e := newEngine(t, WithConfig([]byte(formatConfig)), WithMaxInputBytes(4))
	var errs []error
	_, err := e.ScanString(ctx, input)
	errs = append(errs, err)

	unlimited := newEngine(t, WithConfig([]byte(formatConfig)))
	_, err = unlimited.ScanString(ctx, input, WithBudget(BudgetFindingRecords, 0))
	errs = append(errs, err)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = unlimited.ScanString(cancelled, input)
	errs = append(errs, err)
	unlimited.Close()
	_, err = unlimited.ScanString(ctx, input)
	errs = append(errs, err)
	_, err = unlimited.ScanString(ctx, input, WithDecodeDepth(-1))
	errs = append(errs, err)

	for i, err := range errs {
		if err == nil {
			t.Fatalf("case %d: no error", i)
		}
		checkNoMarker(t, fmt.Sprintf("error %d", i), err.Error())
		checkNoMarker(t, fmt.Sprintf("error %d %%+v", i), fmt.Sprintf("%+v", err))
		var incomplete *IncompleteError
		if errors.As(err, &incomplete) {
			checkNoMarker(t, fmt.Sprintf("error %d %%#v", i), fmt.Sprintf("%#v", *incomplete))
		}
	}
}
