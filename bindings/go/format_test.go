package rustleaks

import (
	"bytes"
	"context"
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
