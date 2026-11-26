package rustleaks

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"slices"
	"strconv"
	"strings"
)

// Rule describes one rule of an engine.
type Rule struct {
	ID          string
	Description string
	Tags        []string
	Keywords    []string
}

// Range is a span of bytes in the scanned input, from Start up to but not
// including End. OK is false when no exact span exists, for example for a
// secret found in decoded text or by a rule that matches only a path.
type Range struct {
	Start int
	End   int
	OK    bool
}

// Finding is one secret that a scan found.
//
// Secret, Match and Line hold the secret. The String, GoString, Format,
// LogValue and MarshalJSON methods leave them out, so fmt, log/slog and
// encoding/json never write them, also for findings in slices, maps and
// struct fields. To store or send those values, copy them into a type of
// your own. Use Redacted for a copy with the secret masked.
type Finding struct {
	// RuleID and Description name the rule that matched.
	RuleID      string
	Description string
	// Tags are the rule tags and, for decoded text, decoding tags such as
	// decoded:base64.
	Tags []string
	// Secret is the secret.
	Secret string
	// Match is the full text that the rule matched.
	Match string
	// Line is the source line that holds the match. Findings of one scan
	// with equal lines share one string.
	Line string
	// StartLine, EndLine, StartColumn and EndColumn give the position of
	// the match with the same values as the rustleaks command reports. A
	// finding of a rule that matches only a path has 0 for all four.
	StartLine   int
	EndLine     int
	StartColumn int
	EndColumn   int
	// SecretRange and MatchRange are the byte offsets of the secret and
	// the match in the input. Use them, not lines and columns, to change
	// the scanned bytes.
	SecretRange Range
	MatchRange  Range
	// Entropy is the Shannon entropy of the secret.
	Entropy float64
	// Path is the path given with WithPath.
	Path string
}

// String returns the rule ID, path and position. It never includes Secret,
// Match or Line.
func (f Finding) String() string {
	var b strings.Builder
	b.WriteString("{RuleID:")
	b.WriteString(f.RuleID)
	b.WriteString(" Path:")
	b.WriteString(f.Path)
	f.writePosition(&b, " ", ":")
	b.WriteString("}")
	return b.String()
}

// GoString returns a Go-syntax view of the rule ID, path and position. It
// never includes Secret, Match or Line.
func (f Finding) GoString() string {
	var b strings.Builder
	b.WriteString("rustleaks.Finding{RuleID:")
	b.WriteString(strconv.Quote(f.RuleID))
	b.WriteString(", Path:")
	b.WriteString(strconv.Quote(f.Path))
	f.writePosition(&b, ", ", ":")
	b.WriteString("}")
	return b.String()
}

func (f Finding) writePosition(b *strings.Builder, sep, colon string) {
	for _, field := range []struct {
		name  string
		value int
	}{
		{"StartLine", f.StartLine},
		{"EndLine", f.EndLine},
		{"StartColumn", f.StartColumn},
		{"EndColumn", f.EndColumn},
	} {
		b.WriteString(sep)
		b.WriteString(field.name)
		b.WriteString(colon)
		b.WriteString(strconv.Itoa(field.value))
	}
}

// Format implements fmt.Formatter so that every verb prints the String or
// GoString form, never the secret.
func (f Finding) Format(s fmt.State, verb rune) {
	switch {
	case verb == 'v' && s.Flag('#'):
		_, _ = io.WriteString(s, f.GoString())
	case verb == 'v' || verb == 's':
		_, _ = io.WriteString(s, f.String())
	case verb == 'q':
		_, _ = io.WriteString(s, strconv.Quote(f.String()))
	default:
		_, _ = fmt.Fprintf(s, "%%!%c(rustleaks.Finding=%s)", verb, f.String())
	}
}

// LogValue implements slog.LogValuer. It logs the rule ID, path and
// position, never the secret.
func (f Finding) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("rule_id", f.RuleID),
		slog.String("path", f.Path),
		slog.Int("start_line", f.StartLine),
		slog.Int("end_line", f.EndLine),
		slog.Int("start_column", f.StartColumn),
		slog.Int("end_column", f.EndColumn),
	)
}

// findingJSON is the JSON form of a Finding: every field but Secret, Match
// and Line.
type findingJSON struct {
	RuleID      string
	Description string
	Tags        []string
	StartLine   int
	EndLine     int
	StartColumn int
	EndColumn   int
	SecretRange Range
	MatchRange  Range
	Entropy     float64
	Path        string
}

// MarshalJSON implements json.Marshaler. It writes every field except
// Secret, Match and Line, under the Go field names, so encoding/json and
// the log/slog JSON handler never write the secret.
func (f Finding) MarshalJSON() ([]byte, error) {
	return json.Marshal(findingJSON{
		RuleID:      f.RuleID,
		Description: f.Description,
		Tags:        f.Tags,
		StartLine:   f.StartLine,
		EndLine:     f.EndLine,
		StartColumn: f.StartColumn,
		EndColumn:   f.EndColumn,
		SecretRange: f.SecretRange,
		MatchRange:  f.MatchRange,
		Entropy:     f.Entropy,
		Path:        f.Path,
	})
}

// Redacted returns a copy with percent of the secret masked, the same way
// as WithRedaction. Secret keeps its first (100 - percent) percent of bytes,
// rounded half to even, followed by "...". At 100 or more, Secret becomes
// REDACTED. The secret is replaced in Match and Line. For a finding in
// decoded text, which has a tag that starts with "decoded:", the whole Line
// is replaced, because it holds the secret in encoded form. At 0 or less,
// Redacted returns an unchanged copy, as WithRedaction(0) masks nothing.
func (f Finding) Redacted(percent int) Finding {
	out := f
	out.Tags = slices.Clone(f.Tags)
	if percent <= 0 {
		return out
	}
	var replacement string
	switch {
	case percent >= 100:
		replacement = "REDACTED"
	case f.Secret == "":
		replacement = ""
	default:
		kept := int(math.RoundToEven(float64(len(f.Secret)) * float64(100-percent) / 100))
		replacement = f.Secret[:kept] + "..."
	}
	decoded := slices.ContainsFunc(f.Tags, func(tag string) bool {
		return strings.HasPrefix(tag, "decoded:")
	})
	if decoded {
		out.Line = replacement
	} else {
		out.Line = strings.ReplaceAll(f.Line, f.Secret, replacement)
	}
	out.Match = strings.ReplaceAll(f.Match, f.Secret, replacement)
	out.Secret = replacement
	return out
}
