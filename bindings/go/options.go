package rustleaks

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"unicode/utf8"
)

// Unlimited turns a budget or the input limit off.
const Unlimited uint64 = math.MaxUint64

// Option configures New.
type Option interface {
	applyEngine(*engineSettings)
}

// ScanOption configures one call of ScanString or ScanBytes.
type ScanOption interface {
	applyScan(*scanSettings)
}

// DetectionOption changes detection. New takes it to set the engine
// default, and ScanString and ScanBytes take it to change one scan.
type DetectionOption struct {
	set func(*detectionSettings)
}

func (o DetectionOption) applyEngine(s *engineSettings) {
	if o.set != nil {
		o.set(&s.detection)
	}
}

func (o DetectionOption) applyScan(s *scanSettings) {
	if o.set != nil {
		o.set(&s.detection)
	}
}

type engineOption func(*engineSettings)

func (f engineOption) applyEngine(s *engineSettings) { f(s) }

type scanOption func(*scanSettings)

func (f scanOption) applyScan(s *scanSettings) { f(s) }

// Base64Mode chooses which base64 text the decoder reads.
type Base64Mode int

const (
	// Base64Compatible, the default, decodes padded standard base64 and
	// unpadded URL-safe base64, and keeps the result only when every
	// decoded byte is in the range 0x09 to 0x7E.
	Base64Compatible Base64Mode = 0
	// Base64Extended also decodes padded URL-safe and unpadded standard
	// base64, and keeps decoded bytes outside that range.
	Base64Extended Base64Mode = 1
)

// String returns the mode name.
func (m Base64Mode) String() string {
	switch m {
	case Base64Compatible:
		return "compatible"
	case Base64Extended:
		return "extended"
	default:
		return "Base64Mode(" + strconv.Itoa(int(m)) + ")"
	}
}

// BudgetKind names a scan budget. See WithBudget.
type BudgetKind int

const (
	// BudgetDecodedBytes limits the bytes the decoder produces.
	BudgetDecodedBytes BudgetKind = iota + 1
	// BudgetWorkUnits limits detection steps. A work unit has no fixed
	// time cost, and the count for one input can change between releases.
	BudgetWorkUnits
	// BudgetFindingRecords limits the number of findings. The default is
	// 100,000.
	BudgetFindingRecords
	// BudgetFindingPayloadBytes limits the bytes held by findings.
	BudgetFindingPayloadBytes
	// BudgetCollectedSpans limits the candidate matches collected.
	BudgetCollectedSpans
	// BudgetNormalizationBytes limits the bytes produced when text is
	// normalized for matching.
	BudgetNormalizationBytes
)

// String returns the budget name.
func (k BudgetKind) String() string {
	switch k {
	case BudgetDecodedBytes:
		return "decoded bytes"
	case BudgetWorkUnits:
		return "work units"
	case BudgetFindingRecords:
		return "finding records"
	case BudgetFindingPayloadBytes:
		return "finding payload bytes"
	case BudgetCollectedSpans:
		return "collected spans"
	case BudgetNormalizationBytes:
		return "normalization bytes"
	default:
		return "BudgetKind(" + strconv.Itoa(int(k)) + ")"
	}
}

const budgetKinds = 6

// setting is an option value and whether the caller set it. Unset values
// keep the library default.
type setting[T any] struct {
	value T
	set   bool
}

func (s *setting[T]) put(v T) { s.value, s.set = v, true }

type detectionSettings struct {
	decodeDepth      setting[uint64]
	base64Mode       setting[Base64Mode]
	redactionPercent setting[uint64]
	allowComments    setting[bool]
	budgets          [budgetKinds]setting[uint64]
	errs             []error
}

func (d *detectionSettings) fail(format string, args ...any) {
	d.errs = append(d.errs, fmt.Errorf("rustleaks: "+format, args...))
}

type engineSettings struct {
	config        []byte
	hasConfig     bool
	rules         []string
	workers       setting[uint64]
	maxInputBytes setting[uint64]
	detection     detectionSettings
}

func (s *engineSettings) err() error { return errors.Join(s.detection.errs...) }

type scanSettings struct {
	path      string
	detection detectionSettings
}

func (s *scanSettings) err() error { return errors.Join(s.detection.errs...) }

// WithConfig builds the engine from a configuration in the Gitleaks TOML
// format instead of the built-in rules. A configuration with
// [extend] useDefault = true keeps the built-in rules and adds its own. A
// configuration with [extend] path fails with a *ConfigError, because the
// package reads no files. The bytes are copied.
func WithConfig(toml []byte) Option {
	config := append([]byte(nil), toml...)
	return engineOption(func(s *engineSettings) {
		s.config, s.hasConfig = config, true
	})
}

// WithRules keeps only the named rules for findings, like the --enable-rule
// flag of the rustleaks command. A rule that a kept rule needs through
// [[rules.required]] stays, but does not report findings. An unknown ID
// makes New fail with a *ConfigError of kind KindRuleSelection. Several
// WithRules options add up.
func WithRules(ids ...string) Option {
	ids = append([]string(nil), ids...)
	return engineOption(func(s *engineSettings) {
		if len(ids) == 0 {
			s.detection.fail("WithRules needs at least one rule ID")
			return
		}
		for _, id := range ids {
			if !utf8.ValidString(id) {
				s.detection.fail("WithRules: rule ID %q is not valid UTF-8", id)
				return
			}
		}
		s.rules = append(s.rules, ids...)
	})
}

// WithWorkers sets how many scans of the engine can run at once. Other
// callers wait for a free worker. The default, 0, means one worker for each
// CPU the process can use, up to 12. The largest value is 256.
func WithWorkers(n int) Option {
	return engineOption(func(s *engineSettings) {
		if n < 0 || n > maxWorkers {
			s.detection.fail("WithWorkers: %d is not between 0 and %d", n, maxWorkers)
			return
		}
		s.workers.put(uint64(n))
	})
}

// WithMaxInputBytes sets the largest input the engine scans, in bytes. An
// input of exactly n bytes is scanned; a longer input fails with an error
// that wraps ErrInputTooLarge. The default is 10,000,000. Unlimited turns
// the limit off.
func WithMaxInputBytes(n uint64) Option {
	return engineOption(func(s *engineSettings) {
		s.maxInputBytes.put(n)
	})
}

// WithPath gives the path of the scanned content. Findings report it, and
// rule path patterns and path allowlists test it. Rules that match only a
// path report a finding even for empty content.
func WithPath(path string) ScanOption {
	return scanOption(func(s *scanSettings) {
		s.path = path
	})
}

// WithDecodeDepth sets how many levels of encoded text the scan decodes:
// base64, hex, percent-encoded and Unicode-escaped text. The default is 0, no
// decoding. The rustleaks command uses 5.
func WithDecodeDepth(depth int) DetectionOption {
	return DetectionOption{func(d *detectionSettings) {
		if depth < 0 {
			d.fail("WithDecodeDepth: %d is negative", depth)
			return
		}
		d.decodeDepth.put(uint64(depth))
	}}
}

// WithBase64Mode chooses which base64 text the decoder reads. The default
// is Base64Compatible. It matters only with a decode depth above 0.
func WithBase64Mode(mode Base64Mode) DetectionOption {
	return DetectionOption{func(d *detectionSettings) {
		if mode != Base64Compatible && mode != Base64Extended {
			d.fail("WithBase64Mode: unknown mode %d", int(mode))
			return
		}
		d.base64Mode.put(mode)
	}}
}

// WithRedaction masks percent of each secret in the findings that the
// library returns: Secret, and the secret inside Match and Line. 100
// replaces the secret with REDACTED. The default is 0, no masking.
func WithRedaction(percent int) DetectionOption {
	return DetectionOption{func(d *detectionSettings) {
		if percent < 0 || percent > 100 {
			d.fail("WithRedaction: %d is not between 0 and 100", percent)
			return
		}
		d.redactionPercent.put(uint64(percent))
	}}
}

// WithAllowComments sets whether a rustleaks:allow or gitleaks:allow
// comment on a line hides the findings on that line. The default is true.
// Set it to false when you scan content that other people write, because
// anyone who can write the content can add the comment.
func WithAllowComments(honor bool) DetectionOption {
	return DetectionOption{func(d *detectionSettings) {
		d.allowComments.put(honor)
	}}
}

// WithBudget limits one kind of scan work to limit units, inclusive. A scan
// that needs more stops with an *IncompleteError. Unlimited turns a budget
// off. Only BudgetFindingRecords has a default, 100,000. Several WithBudget
// options set several budgets.
func WithBudget(kind BudgetKind, limit uint64) DetectionOption {
	return DetectionOption{func(d *detectionSettings) {
		if kind < BudgetDecodedBytes || kind > BudgetNormalizationBytes {
			d.fail("WithBudget: unknown budget kind %d", int(kind))
			return
		}
		d.budgets[kind-1].put(limit)
	}}
}
