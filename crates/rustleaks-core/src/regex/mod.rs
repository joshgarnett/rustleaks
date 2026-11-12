//! Private compatibility layer for Go's `regexp` package.
//!
//! The public crate deliberately exposes pattern source strings, not this
//! backend or any `regex` crate type. The translator covers the RE2 syntax used
//! by the pinned upstream compatibility target while retaining byte offsets
//! for arbitrary source content.

#![forbid(unsafe_code)]
// Some compatibility helpers are exercised only by tests or feature-specific
// consumers.
#![cfg_attr(not(test), allow(dead_code))]

#[cfg(test)]
mod differential;
mod literal_anchor;
#[cfg(test)]
mod validation_tests;

use std::borrow::Cow;
use std::error::Error;
use std::fmt::{self, Write as _};
use std::sync::Arc;

use regex_automata::{
    Input, MatchKind,
    meta::Regex,
    nfa::thompson::{self, WhichCaptures},
    util::{captures::Captures, syntax},
};

pub(crate) use literal_anchor::LiteralAnchorShape;

/// Maximum accepted source-pattern length.
const PATTERN_SIZE_LIMIT: usize = 1 << 20;
/// Maximum heap used by the compiled Thompson NFA.
const COMPILED_SIZE_LIMIT: usize = 256 << 20;
/// Maximum estimated heap used by one `PikeVM` search working set.
const PIKEVM_WORKING_SIZE_LIMIT: usize = 256 << 20;
/// Per-direction lazy-DFA cache capacity; retained and grown on demand.
const HYBRID_CACHE_CAPACITY: usize = 2 << 20;
/// Optional one-pass DFA compilation limit. Larger expressions use fallback engines.
const ONEPASS_SIZE_LIMIT: usize = 1 << 20;
/// Conservative per-state words for sparse sets and epsilon-closure frames.
const PIKEVM_STATE_WORDS: usize = 10;
/// Charge for one anchored search before any scanned byte, in byte equivalents.
///
/// The cache checkout and start-state lookup of a search are charged as if
/// they scanned this many bytes. Every attempt costs at least this much, so a
/// keyword occurring more than once per this many bytes never pays off.
pub(crate) const ATTEMPT_COST_FLOOR: usize = 64;
/// Parser nesting bound. Go's syntax parser separately caps repetition at 1000.
const NEST_LIMIT: u32 = 4_096;
const GO_CAPTURE_NEST_LIMIT: usize = 999;
const MAX_REPEAT: u32 = 1_000;
const DEEP_COMPILE_THRESHOLD: usize = 200;
const DEEP_COMPILE_STACK_SIZE: usize = 32 << 20;
const BACKEND_VERSION: &str = "regex-automata-meta/^0.4.12;regex-syntax/^0.8.5";

/// Private backend requirements retained for compatibility traceability.
pub(crate) const fn backend_version() -> &'static str {
    BACKEND_VERSION
}

// Operational script names from Go 1.26's Unicode 15.0 regexp parser. Go
// canonicalizes an input name before looking it up in `unicode.Scripts`, whose
// multiword keys retain underscores; those keys are consequently unresolvable
// and must not be accepted here. General categories and case folding use the
// compatible regex-syntax backend and can include later Unicode additions.
const GO_UNICODE_SCRIPTS: &str = "
Adlam Ahom Arabic Armenian Avestan Balinese Bamum Batak Bengali Bhaiksuki Bopomofo
Brahmi Braille Buginese Buhid Carian Chakma Cham Cherokee Chorasmian Common Coptic
Cuneiform Cypriot Cyrillic Deseret Devanagari Dogra Duployan Elbasan Elymaic
Ethiopic Georgian Glagolitic Gothic Grantha Greek Gujarati Gurmukhi Han Hangul
Hanunoo Hatran Hebrew Hiragana Inherited Javanese Kaithi Kannada Katakana Kawi
Kharoshthi Khmer Khojki Khudawadi Lao Latin Lepcha Limbu Lisu Lycian Lydian
Mahajani Makasar Malayalam Mandaic Manichaean Marchen Medefaidrin Miao Modi
Mongolian Mro Multani Myanmar Nabataean Nandinagari Newa Nko Nushu Ogham Oriya
Osage Osmanya Palmyrene Phoenician Rejang Runic Samaritan Saurashtra Sharada
Shavian Siddham Sinhala Sogdian Soyombo Sundanese Syriac Tagalog Tagbanwa Takri
Tamil Tangsa Tangut Telugu Thaana Thai Tibetan Tifinagh Tirhuta Toto Ugaritic Vai
Vithkuqi Wancho Yezidi Yi
";
const GO_POSIX_CLASSES: &[&str] = &[
    "[:alnum:]",
    "[:alpha:]",
    "[:ascii:]",
    "[:blank:]",
    "[:cntrl:]",
    "[:digit:]",
    "[:graph:]",
    "[:lower:]",
    "[:print:]",
    "[:punct:]",
    "[:space:]",
    "[:upper:]",
    "[:word:]",
    "[:xdigit:]",
    "[:^alnum:]",
    "[:^alpha:]",
    "[:^ascii:]",
    "[:^blank:]",
    "[:^cntrl:]",
    "[:^digit:]",
    "[:^graph:]",
    "[:^lower:]",
    "[:^print:]",
    "[:^punct:]",
    "[:^space:]",
    "[:^upper:]",
    "[:^word:]",
    "[:^xdigit:]",
];

fn canonical_go_unicode_name(name: &str) -> String {
    let mut canonical = String::with_capacity(name.len());
    for byte in name.bytes() {
        if matches!(byte, b'_' | b'-' | b' ') {
            continue;
        }
        if canonical.is_empty() {
            canonical.push(char::from(byte.to_ascii_uppercase()));
        } else {
            canonical.push(char::from(byte.to_ascii_lowercase()));
        }
    }
    canonical
}

fn go_unicode_property(name: &str) -> Option<String> {
    let canonical = canonical_go_unicode_name(name);
    let direct = match canonical.as_str() {
        "Any" | "Assigned" | "Ascii" => Some(canonical.as_str()),
        "Lc" | "Casedletter" => Some("LC"),
        "C" | "Cc" | "Cf" | "Cn" | "Co" | "Cs" | "L" | "Ll" | "Lm" | "Lo" | "Lt" | "Lu" | "M"
        | "Mc" | "Me" | "Mn" | "N" | "Nd" | "Nl" | "No" | "P" | "Pc" | "Pd" | "Pe" | "Pf"
        | "Pi" | "Po" | "Ps" | "S" | "Sc" | "Sk" | "Sm" | "So" | "Z" | "Zl" | "Zp" | "Zs" => {
            Some(canonical.as_str())
        }
        "Closepunctuation" => Some("Pe"),
        "Combiningmark" | "Mark" => Some("M"),
        "Connectorpunctuation" => Some("Pc"),
        "Control" | "Cntrl" => Some("Cc"),
        "Currencysymbol" => Some("Sc"),
        "Dashpunctuation" => Some("Pd"),
        "Decimalnumber" | "Digit" => Some("Nd"),
        "Enclosingmark" => Some("Me"),
        "Finalpunctuation" => Some("Pf"),
        "Format" => Some("Cf"),
        "Initialpunctuation" => Some("Pi"),
        "Letter" => Some("L"),
        "Letternumber" => Some("Nl"),
        "Lineseparator" => Some("Zl"),
        "Lowercaseletter" => Some("Ll"),
        "Mathsymbol" => Some("Sm"),
        "Modifierletter" => Some("Lm"),
        "Modifiersymbol" => Some("Sk"),
        "Nonspacingmark" => Some("Mn"),
        "Number" => Some("N"),
        "Openpunctuation" => Some("Ps"),
        "Other" => Some("C"),
        "Otherletter" => Some("Lo"),
        "Othernumber" => Some("No"),
        "Otherpunctuation" => Some("Po"),
        "Othersymbol" => Some("So"),
        "Paragraphseparator" => Some("Zp"),
        "Privateuse" => Some("Co"),
        "Punctuation" | "Punct" => Some("P"),
        "Separator" => Some("Z"),
        "Spaceseparator" => Some("Zs"),
        "Spacingmark" => Some("Mc"),
        "Surrogate" => Some("Cs"),
        "Symbol" => Some("S"),
        "Titlecaseletter" => Some("Lt"),
        "Unassigned" => Some("Cn"),
        "Uppercaseletter" => Some("Lu"),
        _ => None,
    };
    if let Some(name) = direct {
        return Some(name.to_owned());
    }
    GO_UNICODE_SCRIPTS
        .split_ascii_whitespace()
        .any(|script| script == canonical)
        .then_some(canonical)
}

/// A half-open byte range returned without leaking the regex backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ByteSpan {
    pub(crate) start: usize,
    pub(crate) end: usize,
}

impl ByteSpan {
    fn from_span(span: regex_automata::Span) -> Self {
        Self {
            start: span.start,
            end: span.end,
        }
    }
}

/// One match and its subexpressions, aligned like Go's `FindSubmatchIndex`.
///
/// Element zero is always the whole match. An unmatched subexpression is
/// represented by `None`, corresponding to Go's `-1, -1` pair.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CaptureSpans {
    spans: Vec<Option<ByteSpan>>,
}

impl CaptureSpans {
    pub(crate) fn spans(&self) -> &[Option<ByteSpan>] {
        &self.spans
    }

    pub(crate) fn whole(&self) -> ByteSpan {
        self.spans[0].expect("a captures result always contains its whole match")
    }
}

/// Reusable storage for repeated capture searches with one [`GoRegex`].
///
/// A scratch value is valid only for the expression that created it. Every
/// search resets the whole-match state and rewrites every reported span, so
/// reuse cannot expose a group from an earlier haystack.
pub(crate) struct CaptureScratch {
    captures: Captures,
    spans: Vec<Option<ByteSpan>>,
}

/// A fallible Go-regexp-compatible compiler error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum GoRegexError {
    PatternTooLarge {
        actual: usize,
        limit: usize,
    },
    WorkingSetTooLarge {
        estimated: Option<usize>,
        limit: usize,
    },
    Syntax {
        offset: usize,
        message: String,
    },
    Backend {
        message: String,
    },
}

impl fmt::Display for GoRegexError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PatternTooLarge { actual, limit } => {
                write!(
                    formatter,
                    "regexp source is {actual} bytes; limit is {limit}"
                )
            }
            Self::WorkingSetTooLarge {
                estimated: Some(estimated),
                limit,
            } => {
                write!(
                    formatter,
                    "regexp PikeVM working set is estimated at {estimated} bytes; limit is {limit}"
                )
            }
            Self::WorkingSetTooLarge {
                estimated: None,
                limit,
            } => {
                write!(
                    formatter,
                    "regexp PikeVM working set estimate overflowed; limit is {limit}"
                )
            }
            Self::Syntax { offset, message } => {
                write!(formatter, "regexp syntax error at byte {offset}: {message}")
            }
            Self::Backend { message } => write!(formatter, "regexp compile error: {message}"),
        }
    }
}

impl Error for GoRegexError {}

/// Immutable compiled expression with Go-style metadata and byte-offset APIs.
#[derive(Clone)]
pub(crate) struct GoRegex {
    source: Box<str>,
    backend: Regex,
    capture_names: Vec<Option<Box<str>>>,
    literal_anchor: Option<Arc<LiteralAnchorShape>>,
}

impl PartialEq for GoRegex {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source
    }
}

impl Eq for GoRegex {}

impl fmt::Debug for GoRegex {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GoRegex")
            .field("source", &self.source)
            .field("capture_names", &self.capture_names)
            .finish_non_exhaustive()
    }
}

impl GoRegex {
    /// Compiles an untrusted Go regexp without panicking.
    pub(crate) fn compile(source: &str) -> Result<Self, GoRegexError> {
        let translated = Self::translate(source)?;
        let (backend, literal_anchor) =
            Self::on_compile_stack(&translated.pattern, Self::build_backend)?;

        Ok(Self {
            source: source.into(),
            backend,
            capture_names: translated.capture_names,
            literal_anchor: literal_anchor.map(Arc::new),
        })
    }

    /// Validates a discarded expression and returns its Go capture count.
    pub(crate) fn validate(source: &str) -> Result<usize, GoRegexError> {
        let translated = Self::translate(source)?;
        Self::on_compile_stack(&translated.pattern, |pattern| {
            Self::preflight(pattern, COMPILED_SIZE_LIMIT).map(drop)
        })?;
        // HIR simplification can erase captures, but Go retains their metadata.
        Ok(translated.capture_names.len() - 1)
    }

    fn translate(source: &str) -> Result<Translation, GoRegexError> {
        if source.len() > PATTERN_SIZE_LIMIT {
            return Err(GoRegexError::PatternTooLarge {
                actual: source.len(),
                limit: PATTERN_SIZE_LIMIT,
            });
        }

        Translator::new(source).translate()
    }

    fn on_compile_stack<T: Send + 'static>(
        pattern: &str,
        build: fn(&str) -> Result<T, GoRegexError>,
    ) -> Result<T, GoRegexError> {
        if pattern.bytes().filter(|byte| *byte == b'(').count() > DEEP_COMPILE_THRESHOLD {
            let pattern = pattern.to_owned();
            std::thread::Builder::new()
                .name("rustleaks-regex-compile".into())
                .stack_size(DEEP_COMPILE_STACK_SIZE)
                .spawn(move || build(&pattern))
                .map_err(|error| GoRegexError::Backend {
                    message: format!("cannot start bounded regex compiler: {error}"),
                })?
                .join()
                .map_err(|_| GoRegexError::Backend {
                    message: "bounded regex compiler panicked".into(),
                })?
        } else {
            build(pattern)
        }
    }

    fn build_backend(pattern: &str) -> Result<(Regex, Option<LiteralAnchorShape>), GoRegexError> {
        let hir = Self::preflight(pattern, COMPILED_SIZE_LIMIT)?;
        let backend = Self::build_meta_backend(&hir, COMPILED_SIZE_LIMIT)?;
        // Analysis runs only after every acceptance decision has been made.
        Ok((backend, LiteralAnchorShape::analyze(&hir)))
    }

    // Validation without a meta matcher depends on the backend's error paths:
    // its forward NFA uses this same configuration; Unicode boundary support
    // is a required feature; reverse-NFA size failures retry without hybrid;
    // full DFA is disabled even under consumer feature unification. Other
    // acceleration failures do not reject patterns. The NFA byte cap precedes
    // state-ID exhaustion on both 32-bit and 64-bit targets. Reaudit these
    // assumptions when dependency versions, features or settings change, and
    // retain exact validator/full-compile error tests plus independent limits.
    fn preflight(
        pattern: &str,
        nfa_size_limit: usize,
    ) -> Result<regex_syntax::hir::Hir, GoRegexError> {
        let hir = syntax::parse_with(
            pattern,
            &syntax::Config::new()
                .unicode(true)
                .utf8(true)
                .nest_limit(NEST_LIMIT),
        )
        .map_err(|_| GoRegexError::Backend {
            // Retain the former Thompson compiler's public error text.
            message: "error parsing regex".into(),
        })?;
        // Meta does not expose its forward NFA. Preserve the existing exact
        // fallback working-set rejection before allocating any search cache.
        // Parse only once and drop this temporary NFA before meta compilation.
        let nfa = thompson::NFA::compiler()
            .configure(
                thompson::Config::new()
                    .utf8(true)
                    .which_captures(WhichCaptures::All)
                    .nfa_size_limit(Some(nfa_size_limit)),
            )
            .build_from_hir(&hir)
            .map_err(|error| GoRegexError::Backend {
                message: error.to_string(),
            })?;
        let estimated = pikevm_working_size(&nfa);
        if estimated.is_none_or(|size| size > PIKEVM_WORKING_SIZE_LIMIT) {
            return Err(GoRegexError::WorkingSetTooLarge {
                estimated,
                limit: PIKEVM_WORKING_SIZE_LIMIT,
            });
        }
        drop(nfa);
        Ok(hir)
    }

    fn build_meta_backend(
        hir: &regex_syntax::hir::Hir,
        nfa_size_limit: usize,
    ) -> Result<Regex, GoRegexError> {
        let config = Regex::config()
            .match_kind(MatchKind::LeftmostFirst)
            .utf8_empty(true)
            .which_captures(WhichCaptures::All)
            .nfa_size_limit(Some(nfa_size_limit))
            .hybrid_cache_capacity(HYBRID_CACHE_CAPACITY)
            .onepass_size_limit(Some(ONEPASS_SIZE_LIMIT))
            // Also prevent eager DFA construction under consumer feature unification.
            .dfa(false);
        let result = Regex::builder()
            .configure(config.clone())
            .build_from_hir(hir);
        let result = match result {
            Err(error) if error.size_limit() == Some(nfa_size_limit) => {
                // The identical forward NFA already passed its limit.
                // A larger reverse NFA must not reject a formerly accepted
                // expression. Retry without building a reverse NFA; every
                // NFA still obeys the same cap.
                Regex::builder()
                    .configure(config.hybrid(false))
                    .build_from_hir(hir)
            }
            result => result,
        };
        result.map_err(|error| GoRegexError::Backend {
            message: error.to_string(),
        })
    }

    pub(crate) fn source(&self) -> &str {
        &self.source
    }

    /// Returns the number of parenthesized subexpressions, excluding the whole
    /// match, exactly like Go's `Regexp.NumSubexp`.
    pub(crate) fn capture_count(&self) -> usize {
        self.capture_names.len() - 1
    }

    /// Returns names aligned to capture indices. Index zero is always `None`,
    /// matching Go's `Regexp.SubexpNames` layout.
    pub(crate) fn capture_names(&self) -> &[Option<Box<str>>] {
        &self.capture_names
    }

    pub(crate) fn is_match(&self, haystack: &[u8]) -> bool {
        let normalized = NormalizedHaystack::new(haystack);
        self.backend.is_match(normalized.bytes())
    }

    /// Eagerly returns whole-match spans without computing capture groups.
    pub(crate) fn find_all(&self, haystack: &[u8]) -> Vec<ByteSpan> {
        self.find_all_normalized(&NormalizedHaystack::new(haystack))
    }

    pub(crate) fn find_all_normalized(&self, normalized: &NormalizedHaystack<'_>) -> Vec<ByteSpan> {
        let bytes = normalized.bytes();
        let end = bytes.len();
        let mut position = 0;
        let mut previous_match_end = None;
        let mut results = Vec::new();
        let mut original_cursor = 0;
        while position <= end {
            let Some(whole) = self.backend.search(&Input::new(bytes).span(position..end)) else {
                break;
            };
            let mut accept = true;
            if whole.end() == position {
                // Go suppresses an empty match at the preceding match end,
                // then advances one decoded rune. Keep enumeration eager so
                // the engine's cancellation and work checkpoints do not move.
                if previous_match_end == Some(whole.start()) {
                    accept = false;
                }
                let width = utf8_rune_width(&bytes[position..]);
                if width == 0 {
                    position = end + 1;
                } else {
                    position += width;
                }
            } else {
                position = whole.end();
            }
            previous_match_end = Some(whole.end());
            if accept {
                results.push(normalized.original_span_in_order(
                    ByteSpan {
                        start: whole.start(),
                        end: whole.end(),
                    },
                    &mut original_cursor,
                ));
            }
        }
        results
    }

    /// Finds only the first match, treating this slice as its own haystack.
    pub(crate) fn captures(&self, haystack: &[u8]) -> Option<CaptureSpans> {
        let mut scratch = self.capture_scratch();
        self.captures_into(haystack, &mut scratch)?;
        Some(CaptureSpans {
            spans: scratch.spans,
        })
    }

    /// Creates storage for [`Self::captures_into`] on this expression.
    pub(crate) fn capture_scratch(&self) -> CaptureScratch {
        CaptureScratch {
            captures: self.backend.create_captures(),
            spans: Vec::with_capacity(self.capture_names.len()),
        }
    }

    /// Finds only the first match, like [`Self::captures`], using `scratch`.
    ///
    /// The returned slice is aligned like [`CaptureSpans::spans`].
    pub(crate) fn captures_into<'s>(
        &self,
        haystack: &[u8],
        scratch: &'s mut CaptureScratch,
    ) -> Option<&'s [Option<ByteSpan>]> {
        let normalized = NormalizedHaystack::new(haystack);
        self.backend
            .search_captures(&Input::new(normalized.bytes()), &mut scratch.captures);
        scratch.captures.get_group(0)?;
        scratch.spans.clear();
        scratch
            .spans
            .extend((0..self.capture_names.len()).map(|index| {
                scratch
                    .captures
                    .get_group(index)
                    .map(|span| normalized.original_span(ByteSpan::from_span(span)))
            }));
        Some(&scratch.spans)
    }

    /// Returns every non-overlapping match and all of its capture spans.
    pub(crate) fn captures_all(&self, haystack: &[u8]) -> Vec<CaptureSpans> {
        let normalized = NormalizedHaystack::new(haystack);
        let bytes = normalized.bytes();
        let end = bytes.len();
        let mut position = 0;
        let mut previous_match_end = None;
        let mut results = Vec::new();
        let mut captures = self.backend.create_captures();

        while position <= end {
            self.backend
                .search_captures(&Input::new(bytes).span(position..end), &mut captures);
            let Some(whole) = captures.get_group(0) else {
                break;
            };
            let mut accept = true;

            if whole.end == position {
                // This is the same progression rule as Go regexp's allMatches:
                // suppress an empty match immediately after the previous
                // result, then advance one decoded rune (RuneError width one).
                if previous_match_end == Some(whole.start) {
                    accept = false;
                }
                let width = utf8_rune_width(&bytes[position..]);
                if width == 0 {
                    position = end + 1;
                } else {
                    position += width;
                }
            } else {
                position = whole.end;
            }
            previous_match_end = Some(whole.end);

            if accept {
                results.push(CaptureSpans {
                    spans: (0..self.capture_names.len())
                        .map(|index| {
                            captures
                                .get_group(index)
                                .map(|span| normalized.original_span(ByteSpan::from_span(span)))
                        })
                        .collect(),
                });
            }
        }
        results
    }
}

/// Conservatively estimates the heap that one `PikeVM` search can retain.
///
/// The dependency allocates two capture-slot tables, two sparse state sets,
/// one epsilon-closure stack, and caller-visible capture slots. Its private
/// state identifiers are no wider than `usize`; `PIKEVM_STATE_WORDS`
/// deliberately overestimates the combined state-set and stack storage.
fn pikevm_working_size(nfa: &thompson::NFA) -> Option<usize> {
    let states = nfa.states().len();
    let slots = nfa.group_info().slot_len();
    let scratch_slots = slots.max(nfa.pattern_len().checked_mul(2)?);
    let table_slots = states.checked_mul(slots)?.checked_add(scratch_slots)?;
    let all_slot_words = table_slots.checked_mul(2)?.checked_add(slots)?;
    let state_words = states.checked_mul(PIKEVM_STATE_WORDS)?;
    all_slot_words
        .checked_add(state_words)?
        .checked_mul(std::mem::size_of::<usize>())
}

pub(crate) struct NormalizedHaystack<'a> {
    bytes: Cow<'a, [u8]>,
    /// Normalized start of each replacement for one invalid source byte.
    replacement_starts: Vec<usize>,
}

impl<'a> NormalizedHaystack<'a> {
    pub(crate) fn new(original: &'a [u8]) -> Self {
        let Err(error) = std::str::from_utf8(original) else {
            return Self {
                bytes: Cow::Borrowed(original),
                replacement_starts: Vec::new(),
            };
        };

        // At least one invalid byte is known, so two expansion bytes avoid a
        // reallocation when the only invalid byte occurs late in a large input.
        let mut bytes = Vec::with_capacity(original.len().saturating_add(2));
        let mut replacement_starts = Vec::new();
        // The initial validation already checked this prefix. Copy valid runs
        // in bulk and retain offsets only where normalization expands bytes.
        let valid_prefix = error.valid_up_to();
        bytes.extend_from_slice(&original[..valid_prefix]);
        for chunk in original[valid_prefix..].utf8_chunks() {
            bytes.extend_from_slice(chunk.valid().as_bytes());
            // A Rust UTF-8 error can cover several source bytes. Go consumes
            // each malformed or truncated byte as its own RuneError.
            for _ in chunk.invalid() {
                replacement_starts.push(bytes.len());
                bytes.extend_from_slice("\u{fffd}".as_bytes());
            }
        }
        Self {
            bytes: Cow::Owned(bytes),
            replacement_starts,
        }
    }

    fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn original_span(&self, normalized: ByteSpan) -> ByteSpan {
        if self.replacement_starts.is_empty() {
            return normalized;
        }
        ByteSpan {
            start: self.original_offset(normalized.start),
            end: self.original_offset(normalized.end),
        }
    }

    fn original_offset(&self, normalized: usize) -> usize {
        let count = self
            .replacement_starts
            .partition_point(|start| *start <= normalized);
        self.offset_with_count(normalized, count)
    }

    fn original_span_in_order(&self, normalized: ByteSpan, cursor: &mut usize) -> ByteSpan {
        if self.replacement_starts.is_empty() {
            return normalized;
        }
        let start = self.original_offset_in_order(normalized.start, cursor);
        let end = if normalized.start == normalized.end {
            start
        } else {
            self.original_offset_in_order(normalized.end, cursor)
        };
        ByteSpan { start, end }
    }

    fn original_offset_in_order(&self, normalized: usize, cursor: &mut usize) -> usize {
        debug_assert!(*cursor == 0 || self.replacement_starts[*cursor - 1] <= normalized);
        // Whole matches are ordered and nonoverlapping. Nearby endpoints can
        // advance cheaply; a large jump still uses logarithmic lookup rather
        // than walking every invalid byte skipped by the regex.
        for _ in 0..8 {
            if self
                .replacement_starts
                .get(*cursor)
                .is_none_or(|start| *start > normalized)
            {
                return self.offset_with_count(normalized, *cursor);
            }
            *cursor += 1;
        }
        *cursor += self.replacement_starts[*cursor..].partition_point(|start| *start <= normalized);
        self.offset_with_count(normalized, *cursor)
    }

    fn offset_with_count(&self, normalized: usize, count: usize) -> usize {
        if count == 0 {
            return normalized;
        }
        let last = self.replacement_starts[count - 1];
        if normalized - last < 3 {
            // All three boundaries within a replacement map to the invalid
            // source byte. Its following boundary maps past that byte.
            last - 2 * (count - 1)
        } else {
            // Each preceding replacement expands one source byte into three.
            normalized - 2 * count
        }
    }
}

/// Returns Go `utf8.DecodeRune`'s width for the first rune in `bytes`.
/// Invalid and truncated encodings consume one byte as `utf8.RuneError`.
fn utf8_rune_width(bytes: &[u8]) -> usize {
    let Some(&first) = bytes.first() else {
        return 0;
    };
    if first.is_ascii() {
        return 1;
    }
    let expected = match first {
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        _ => return 1,
    };
    let Some(candidate) = bytes.get(..expected) else {
        return 1;
    };
    if std::str::from_utf8(candidate).is_ok() {
        expected
    } else {
        1
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Flags {
    multi_line: bool,
    swap_greed: bool,
}

#[derive(Debug)]
struct Translation {
    pattern: String,
    capture_names: Vec<Option<Box<str>>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RepeatState {
    None,
    Quantifier,
    Lazy,
}

struct Translator<'a> {
    source: &'a str,
    bytes: &'a [u8],
    offset: usize,
    output: String,
    flags: Flags,
    group_flags: Vec<Flags>,
    group_capturing: Vec<bool>,
    group_output_starts: Vec<usize>,
    capture_depth: usize,
    capture_names: Vec<Option<Box<str>>>,
    repeat_state: RepeatState,
    last_group_was_directive: bool,
    can_repeat: bool,
    pending_flag_directives: String,
    current_operand_start: Option<usize>,
    current_operand_swap_greed: bool,
    expression_repeat_product: u32,
    current_operand_repeat_product: u32,
    group_repeat_products: Vec<u32>,
    repeat_wrap_start: Option<usize>,
}

impl<'a> Translator<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source,
            bytes: source.as_bytes(),
            offset: 0,
            output: String::with_capacity(source.len()),
            flags: Flags::default(),
            group_flags: Vec::new(),
            group_capturing: Vec::new(),
            group_output_starts: Vec::new(),
            capture_depth: 0,
            capture_names: vec![None],
            repeat_state: RepeatState::None,
            last_group_was_directive: false,
            can_repeat: false,
            pending_flag_directives: String::new(),
            current_operand_start: None,
            current_operand_swap_greed: false,
            expression_repeat_product: 0,
            current_operand_repeat_product: 0,
            group_repeat_products: Vec::new(),
            repeat_wrap_start: None,
        }
    }

    fn translate(mut self) -> Result<Translation, GoRegexError> {
        while self.offset < self.bytes.len() {
            match self.bytes[self.offset] {
                b'\\' => {
                    self.begin_atom();
                    self.translate_escape()?;
                    self.repeat_state = RepeatState::None;
                    self.can_repeat = true;
                }
                b'[' => {
                    self.begin_atom();
                    self.translate_class()?;
                    self.repeat_state = RepeatState::None;
                    self.can_repeat = true;
                }
                b'(' => {
                    let previous_repeat_state = self.repeat_state;
                    let previous_can_repeat = self.can_repeat;
                    self.last_group_was_directive = false;
                    self.translate_group_start()?;
                    if self.last_group_was_directive {
                        if previous_repeat_state != RepeatState::None {
                            self.repeat_wrap_start = self.current_operand_start;
                        }
                        self.repeat_state = RepeatState::None;
                        self.can_repeat = previous_can_repeat;
                    } else {
                        self.repeat_state = RepeatState::None;
                        self.can_repeat = false;
                    }
                }
                b')' => {
                    self.repeat_wrap_start = None;
                    self.pending_flag_directives.clear();
                    self.output.push(')');
                    self.offset += 1;
                    if let Some(flags) = self.group_flags.pop() {
                        self.flags = flags;
                    }
                    if self.group_capturing.pop() == Some(true) {
                        self.capture_depth -= 1;
                    }
                    self.current_operand_start = self.group_output_starts.pop();
                    self.current_operand_swap_greed = self.flags.swap_greed;
                    if let Some(outer_product) = self.group_repeat_products.pop() {
                        self.current_operand_repeat_product = self.expression_repeat_product.max(1);
                        self.expression_repeat_product =
                            outer_product.max(self.current_operand_repeat_product);
                    }
                    self.repeat_state = RepeatState::None;
                    self.can_repeat = true;
                }
                b'{' => self.translate_left_brace()?,
                b'}' => {
                    self.begin_atom();
                    self.output.push_str(r"\}");
                    self.offset += 1;
                    self.repeat_state = RepeatState::None;
                    self.can_repeat = true;
                }
                b'$' if !self.flags.multi_line => {
                    self.begin_atom();
                    self.output.push_str(r"\z");
                    self.offset += 1;
                    self.repeat_state = RepeatState::None;
                    self.can_repeat = true;
                }
                b'.' => {
                    self.begin_atom();
                    self.output.push('.');
                    self.offset += 1;
                    self.repeat_state = RepeatState::None;
                    self.can_repeat = true;
                }
                b'*' | b'+' | b'?' => self.translate_simple_repetition()?,
                b'|' => {
                    self.repeat_wrap_start = None;
                    self.output.push('|');
                    self.offset += 1;
                    self.repeat_state = RepeatState::None;
                    self.can_repeat = false;
                    self.current_operand_start = None;
                    self.current_operand_repeat_product = 0;
                }
                _ => {
                    self.begin_atom();
                    self.copy_char();
                    self.repeat_state = RepeatState::None;
                    self.can_repeat = true;
                }
            }
        }

        Ok(Translation {
            pattern: self.output,
            capture_names: self.capture_names,
        })
    }

    fn copy_char(&mut self) {
        let ch = self.source[self.offset..]
            .chars()
            .next()
            .expect("offset is within source");
        self.output.push(ch);
        self.offset += ch.len_utf8();
    }

    fn flush_pending_flags(&mut self) {
        self.output.push_str(&self.pending_flag_directives);
        self.pending_flag_directives.clear();
    }

    fn begin_atom(&mut self) {
        self.repeat_wrap_start = None;
        self.flush_pending_flags();
        self.current_operand_start = Some(self.output.len());
        self.current_operand_swap_greed = self.flags.swap_greed;
        self.current_operand_repeat_product = 1;
        self.expression_repeat_product = self.expression_repeat_product.max(1);
    }

    fn begin_group(&mut self) {
        self.group_repeat_products
            .push(self.expression_repeat_product);
        self.expression_repeat_product = 0;
        self.current_operand_repeat_product = 0;
    }

    fn prepare_repetition(&mut self) {
        if let Some(start) = self.repeat_wrap_start.take() {
            self.output.insert_str(start, "(?:");
            self.output.push(')');
            self.current_operand_start = Some(start);
        }
    }

    fn repetition_greed_is_inverted(&self) -> bool {
        self.flags.swap_greed != self.current_operand_swap_greed
    }

    fn translate_escape(&mut self) -> Result<(), GoRegexError> {
        let start = self.offset;
        self.offset += 1;
        let Some(&escaped) = self.bytes.get(self.offset) else {
            return Err(Self::syntax(start, "trailing backslash"));
        };

        match escaped {
            b'd' => self.output.push_str(r"(?-u:[0-9])"),
            b's' => self.output.push_str(r"(?-u:[\t\n\f\r ])"),
            b'w' => self.output.push_str(r"[A-Za-z0-9_]"),
            b'D' => self.output.push_str(r"[^0-9]"),
            b'S' => self.output.push_str(r"[^\t\n\f\r ]"),
            b'W' => self.output.push_str(r"[^A-Za-z0-9_]"),
            b'b' => self.output.push_str(r"(?-u:\b)"),
            b'B' => self.output.push_str(r"(?-u:\B)"),
            b'Q' => {
                self.offset += 1;
                self.translate_quoted_literal();
                return Ok(());
            }
            b'x' => {
                self.translate_hex_escape(start)?;
                return Ok(());
            }
            b'p' | b'P' => {
                self.translate_unicode_class_escape(start)?;
                return Ok(());
            }
            b'0' => {
                let (end, value) = self.octal_escape();
                let _ = write!(self.output, r"\x{{{value:X}}}");
                self.offset = end;
                return Ok(());
            }
            b'1'..=b'7'
                if self
                    .bytes
                    .get(self.offset + 1)
                    .is_some_and(|byte| matches!(byte, b'0'..=b'7')) =>
            {
                let (end, value) = self.octal_escape();
                let _ = write!(self.output, r"\x{{{value:X}}}");
                self.offset = end;
                return Ok(());
            }
            b'a' => self.output.push_str(r"\x{7}"),
            b'v' => self.output.push_str(r"\x{B}"),
            b'C' | b'R' | b'X' | b'Z' | b'u' | b'U' | b'1'..=b'9' => {
                return Err(Self::syntax(start, "invalid or unsupported Go escape"));
            }
            byte @ (b'n' | b'r' | b't' | b'f' | b'A' | b'z') => {
                self.output.push('\\');
                self.output.push(char::from(byte));
            }
            byte if byte.is_ascii_alphabetic() => {
                return Err(Self::syntax(start, "invalid Go escape"));
            }
            byte if byte.is_ascii() => {
                let _ = write!(self.output, r"\x{{{byte:X}}}");
            }
            _ => return Err(Self::syntax(start, "invalid Go escape")),
        }
        self.offset += 1;
        Ok(())
    }

    fn translate_hex_escape(&mut self, start: usize) -> Result<(), GoRegexError> {
        let (end, value) = self.parse_hex_escape(start)?;
        if (0xD800..=0xDFFF).contains(&value) {
            self.output.push_str(r"[\x00&&\x01]");
        } else {
            let _ = write!(self.output, r"\x{{{value:X}}}");
        }
        self.offset = end;
        Ok(())
    }

    fn parse_hex_escape(&self, start: usize) -> Result<(usize, u32), GoRegexError> {
        let payload = start + 2;
        if self.bytes.get(payload) == Some(&b'{') {
            let digits_start = payload + 1;
            let Some(relative_end) = self.source[digits_start..].find('}') else {
                return Err(Self::syntax(start, "unclosed hexadecimal escape"));
            };
            let digits_end = digits_start + relative_end;
            let digits = &self.source[digits_start..digits_end];
            if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(Self::syntax(start, "invalid hexadecimal escape"));
            }
            let significant = digits.trim_start_matches('0');
            let value = if significant.is_empty() {
                0
            } else {
                u32::from_str_radix(significant, 16)
                    .map_err(|_| Self::syntax(start, "invalid hexadecimal escape"))?
            };
            if value > char::MAX as u32 {
                return Err(Self::syntax(start, "invalid hexadecimal escape"));
            }
            return Ok((digits_end + 1, value));
        }

        let Some(digits_end) = payload.checked_add(2) else {
            return Err(Self::syntax(start, "invalid hexadecimal escape"));
        };
        let Some(digits) = self.bytes.get(payload..digits_end) else {
            return Err(Self::syntax(start, "invalid hexadecimal escape"));
        };
        if !digits.iter().all(u8::is_ascii_hexdigit) {
            return Err(Self::syntax(start, "invalid hexadecimal escape"));
        }
        let value = u32::from_str_radix(
            std::str::from_utf8(digits).expect("hexadecimal digits are ASCII"),
            16,
        )
        .expect("two validated hexadecimal digits fit in u32");
        Ok((digits_end, value))
    }

    fn translate_unicode_class_escape(&mut self, start: usize) -> Result<(), GoRegexError> {
        let (end, escape) = self.parse_unicode_class_escape(start)?;
        self.output.push_str(&escape);
        self.offset = end;
        Ok(())
    }

    fn parse_unicode_class_escape(&self, start: usize) -> Result<(usize, String), GoRegexError> {
        let marker = self.bytes[start + 1];
        let payload = start + 2;
        let end = if self.bytes.get(payload) == Some(&b'{') {
            let name_start = payload + 1;
            let Some(relative_end) = self.source[name_start..].find('}') else {
                return Err(Self::syntax(start, "unclosed Unicode class escape"));
            };
            let name_end = name_start + relative_end;
            if name_end == name_start {
                return Err(Self::syntax(start, "empty Unicode class escape"));
            }
            name_end + 1
        } else {
            let Some(ch) = self.source[payload..].chars().next() else {
                return Err(Self::syntax(start, "missing Unicode class name"));
            };
            payload + ch.len_utf8()
        };
        let mut name = if self.bytes.get(payload) == Some(&b'{') {
            &self.source[payload + 1..end - 1]
        } else {
            &self.source[payload..end]
        };
        let mut negative = marker == b'P';
        if let Some(stripped) = name.strip_prefix('^') {
            negative = !negative;
            name = stripped;
        }
        let Some(property) = go_unicode_property(name) else {
            return Err(Self::syntax(start, "invalid Go Unicode property"));
        };
        let translated = if property == "Cs" {
            if negative {
                r"\p{Any}".to_owned()
            } else {
                r"[\x00&&\x01]".to_owned()
            }
        } else {
            let marker = if negative { 'P' } else { 'p' };
            format!(r"\{marker}{{{property}}}")
        };
        Ok((end, translated))
    }

    fn translate_quoted_literal(&mut self) {
        let rest = &self.source[self.offset..];
        let end = rest.find(r"\E").unwrap_or(rest.len());
        regex_syntax::escape_into(&rest[..end], &mut self.output);
        self.offset += end;
        if self.source[self.offset..].starts_with(r"\E") {
            self.offset += 2;
        }
    }

    fn octal_escape(&self) -> (usize, u32) {
        let mut end = self.offset;
        let mut value = 0;
        while end < self.bytes.len()
            && end < self.offset + 3
            && matches!(self.bytes[end], b'0'..=b'7')
        {
            value = (value << 3) | u32::from(self.bytes[end] - b'0');
            end += 1;
        }
        (end, value)
    }

    fn translate_class(&mut self) -> Result<(), GoRegexError> {
        let start = self.offset;
        self.offset += 1;
        let mut translated = String::from("[");
        if self.bytes.get(self.offset) == Some(&b'^') {
            translated.push('^');
            self.offset += 1;
        }

        let mut first = true;
        loop {
            let Some(&byte) = self.bytes.get(self.offset) else {
                return Err(Self::syntax(start, "unclosed character class"));
            };
            if byte == b']' && !first {
                translated.push(']');
                self.offset += 1;
                break;
            }
            first = false;

            if self.translate_class_group(&mut translated)? {
                continue;
            }

            let (after_low, low) = self.parse_class_rune(self.offset, start)?;
            self.offset = after_low;
            let mut high = low;
            if self.bytes.get(self.offset) == Some(&b'-')
                && self
                    .bytes
                    .get(self.offset + 1)
                    .is_some_and(|byte| *byte != b']')
            {
                self.offset += 1;
                let (after_high, parsed_high) = self.parse_class_rune(self.offset, start)?;
                if parsed_high < low {
                    return Err(Self::syntax(
                        self.offset,
                        "invalid Go character class range",
                    ));
                }
                self.offset = after_high;
                high = parsed_high;
            }
            Self::push_class_range(&mut translated, low, high);
        }

        self.output.push_str(&translated);
        Ok(())
    }

    fn translate_class_group(&mut self, translated: &mut String) -> Result<bool, GoRegexError> {
        if self.source[self.offset..].starts_with("[:") {
            let name_start = self.offset + 2;
            if let Some(relative_end) = self.source[name_start..].find(":]") {
                let name_end = name_start + relative_end;
                let token = &self.source[self.offset..name_end + 2];
                if !GO_POSIX_CLASSES.contains(&token) {
                    return Err(Self::syntax(
                        self.offset,
                        "invalid Go POSIX character class",
                    ));
                }
                translated.push_str(token);
                self.offset = name_end + 2;
                return Ok(true);
            }
        }
        if self.bytes.get(self.offset) != Some(&b'\\') {
            return Ok(false);
        }
        match self.bytes.get(self.offset + 1) {
            Some(b'd') => translated.push_str("0-9"),
            Some(b's') => translated.push_str(r"\t\n\f\r "),
            Some(b'w') => translated.push_str("A-Za-z0-9_"),
            Some(b'D') => translated.push_str("[^0-9]"),
            Some(b'S') => translated.push_str(r"[^\t\n\f\r ]"),
            Some(b'W') => translated.push_str("[^A-Za-z0-9_]"),
            Some(b'p' | b'P') => {
                let (end, property) = self.parse_unicode_class_escape(self.offset)?;
                translated.push_str(&property);
                self.offset = end;
                return Ok(true);
            }
            _ => return Ok(false),
        }
        self.offset += 2;
        Ok(true)
    }

    fn parse_class_rune(
        &self,
        offset: usize,
        class_start: usize,
    ) -> Result<(usize, u32), GoRegexError> {
        let Some(&byte) = self.bytes.get(offset) else {
            return Err(Self::syntax(class_start, "unclosed character class"));
        };
        if byte != b'\\' {
            let ch = self.source[offset..]
                .chars()
                .next()
                .expect("offset is within source");
            return Ok((offset + ch.len_utf8(), ch as u32));
        }
        let Some(&escaped) = self.bytes.get(offset + 1) else {
            return Err(Self::syntax(
                offset,
                "trailing backslash in character class",
            ));
        };
        if escaped == b'x' {
            return self.parse_hex_escape(offset);
        }
        if matches!(escaped, b'0'..=b'7') {
            if escaped != b'0'
                && !self
                    .bytes
                    .get(offset + 2)
                    .is_some_and(|byte| matches!(byte, b'0'..=b'7'))
            {
                return Err(Self::syntax(offset, "invalid Go character-class escape"));
            }
            let mut end = offset + 1;
            let mut value = 0;
            while end < self.bytes.len()
                && end < offset + 4
                && matches!(self.bytes[end], b'0'..=b'7')
            {
                value = (value << 3) | u32::from(self.bytes[end] - b'0');
                end += 1;
            }
            return Ok((end, value));
        }
        let value = match escaped {
            b'a' => 0x07,
            b'f' => 0x0C,
            b'n' => 0x0A,
            b'r' => 0x0D,
            b't' => 0x09,
            b'v' => 0x0B,
            byte if byte.is_ascii() && !byte.is_ascii_alphanumeric() => u32::from(byte),
            _ => return Err(Self::syntax(offset, "invalid Go character-class escape")),
        };
        Ok((offset + 2, value))
    }

    fn push_class_rune(translated: &mut String, rune: u32) {
        let _ = write!(translated, r"\x{{{rune:X}}}");
    }

    fn push_class_range(translated: &mut String, low: u32, high: u32) {
        if low < 0xD800 && high > 0xDFFF {
            Self::push_class_rune(translated, low);
            translated.push('-');
            Self::push_class_rune(translated, high);
        } else if low < 0xD800 {
            let scalar_high = high.min(0xD7FF);
            Self::push_class_rune(translated, low);
            if scalar_high != low {
                translated.push('-');
                Self::push_class_rune(translated, scalar_high);
            }
        } else if high > 0xDFFF {
            let scalar_low = low.max(0xE000);
            Self::push_class_rune(translated, scalar_low);
            if high != scalar_low {
                translated.push('-');
                Self::push_class_rune(translated, high);
            }
        } else {
            translated.push_str(r"[\x00&&\x01]");
        }
    }

    fn translate_group_start(&mut self) -> Result<(), GoRegexError> {
        let start = self.offset;
        if !self.source[self.offset..].starts_with("(?") {
            self.repeat_wrap_start = None;
            self.flush_pending_flags();
            let output_start = self.output.len();
            self.begin_capturing_group(start)?;
            self.begin_group();
            self.output.push('(');
            self.offset += 1;
            self.group_flags.push(self.flags);
            self.group_capturing.push(true);
            self.group_output_starts.push(output_start);
            self.capture_names.push(None);
            return Ok(());
        }

        if self.source[self.offset..].starts_with("(?:") {
            self.repeat_wrap_start = None;
            self.flush_pending_flags();
            let output_start = self.output.len();
            self.begin_group();
            self.output.push_str("(?:");
            self.offset += 3;
            self.group_flags.push(self.flags);
            self.group_capturing.push(false);
            self.group_output_starts.push(output_start);
            return Ok(());
        }

        if self.source[self.offset..].starts_with("(?P<")
            || (self.source[self.offset..].starts_with("(?<")
                && !self.source[self.offset..].starts_with("(?<=")
                && !self.source[self.offset..].starts_with("(?<!"))
        {
            return self.translate_named_group();
        }

        self.translate_flags(start)
    }

    fn translate_named_group(&mut self) -> Result<(), GoRegexError> {
        let start = self.offset;
        self.repeat_wrap_start = None;
        self.flush_pending_flags();
        let output_start = self.output.len();
        self.begin_capturing_group(start)?;
        let prefix_len = if self.source[self.offset..].starts_with("(?P<") {
            4
        } else {
            3
        };
        let name_start = self.offset + prefix_len;
        let Some(relative_end) = self.source[name_start..].find('>') else {
            return Err(Self::syntax(start, "unclosed named capture"));
        };
        let name_end = name_start + relative_end;
        let name = &self.source[name_start..name_end];
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(Self::syntax(name_start, "invalid Go capture name"));
        }

        let index = self.capture_names.len();
        self.begin_group();
        self.output.push_str("(?P<g");
        self.output.push_str(&index.to_string());
        self.output.push('>');
        self.capture_names.push(Some(name.into()));
        self.group_flags.push(self.flags);
        self.group_capturing.push(true);
        self.group_output_starts.push(output_start);
        self.offset = name_end + 1;
        Ok(())
    }

    fn begin_capturing_group(&mut self, offset: usize) -> Result<(), GoRegexError> {
        if self.capture_depth == GO_CAPTURE_NEST_LIMIT {
            return Err(Self::syntax(offset, "expression nests too deeply"));
        }
        self.capture_depth += 1;
        Ok(())
    }

    fn translate_flags(&mut self, start: usize) -> Result<(), GoRegexError> {
        let mut cursor = self.offset + 2;
        let mut enable = true;
        let mut updated = self.flags;
        let mut saw_flag = false;
        let mut requested_enable = [false; 4];
        let mut requested_disable = [false; 4];

        loop {
            let Some(&byte) = self.bytes.get(cursor) else {
                return Err(Self::syntax(start, "unclosed flag group"));
            };
            match byte {
                flag @ (b'i' | b'm' | b's' | b'U') => {
                    saw_flag = true;
                    let index = match flag {
                        b'i' => 0,
                        b'm' => 1,
                        b's' => 2,
                        b'U' => 3,
                        _ => unreachable!(),
                    };
                    if enable {
                        requested_enable[index] = true;
                    } else {
                        requested_disable[index] = true;
                    }
                    match flag {
                        b'm' => updated.multi_line = enable,
                        b'U' => updated.swap_greed = enable,
                        _ => {}
                    }
                }
                b'-' if enable => enable = false,
                b':' | b')' if saw_flag => {
                    let terminator = byte;
                    let mut directive = String::from("(?");
                    for (index, flag) in b"imsU".iter().copied().enumerate() {
                        if requested_enable[index] && !requested_disable[index] {
                            directive.push(char::from(flag));
                        }
                    }
                    if requested_disable.iter().any(|requested| *requested) {
                        directive.push('-');
                        for (index, flag) in b"imsU".iter().copied().enumerate() {
                            if requested_disable[index] {
                                directive.push(char::from(flag));
                            }
                        }
                    }
                    directive.push(char::from(terminator));
                    self.offset = cursor + 1;
                    if terminator == b':' {
                        self.repeat_wrap_start = None;
                        self.flush_pending_flags();
                        let output_start = self.output.len();
                        self.begin_group();
                        self.output.push_str(&directive);
                        self.group_flags.push(self.flags);
                        self.group_capturing.push(false);
                        self.group_output_starts.push(output_start);
                        self.flags = updated;
                    } else {
                        self.flags = updated;
                        self.pending_flag_directives.push_str(&directive);
                        self.last_group_was_directive = true;
                    }
                    return Ok(());
                }
                b')' if cursor == self.offset + 2 => {
                    self.offset = cursor + 1;
                    self.last_group_was_directive = true;
                    return Ok(());
                }
                b':' | b')' => return Err(Self::syntax(start, "empty flag group")),
                _ => return Err(Self::syntax(cursor, "unsupported Go group or flag")),
            }
            cursor += 1;
        }
    }

    fn translate_left_brace(&mut self) -> Result<(), GoRegexError> {
        let start = self.offset;
        if let Some((end, minimum, maximum)) = self.repetition() {
            if !self.can_repeat || self.repeat_state != RepeatState::None {
                return Err(Self::syntax(start, "invalid nested repetition operator"));
            }
            if minimum > MAX_REPEAT || maximum.is_some_and(|value| value > MAX_REPEAT) {
                return Err(Self::syntax(start, "invalid repeat count: maximum is 1000"));
            }
            if maximum.is_some_and(|value| value < minimum) {
                return Err(Self::syntax(
                    start,
                    "invalid repeat count: minimum exceeds maximum",
                ));
            }
            self.apply_repeat_product(start, minimum, maximum)?;
            self.prepare_repetition();
            self.output.push_str(&self.source[start..end]);
            if self.repetition_greed_is_inverted() {
                self.output.push('?');
            }
            self.offset = end;
            self.repeat_state = RepeatState::Quantifier;
            self.can_repeat = true;
        } else {
            self.begin_atom();
            self.output.push_str(r"\{");
            self.offset += 1;
            self.repeat_state = RepeatState::None;
            self.can_repeat = true;
        }
        Ok(())
    }

    fn apply_repeat_product(
        &mut self,
        offset: usize,
        minimum: u32,
        maximum: Option<u32>,
    ) -> Result<(), GoRegexError> {
        let factor = maximum.unwrap_or(minimum);
        if (minimum >= 2 || maximum.is_some_and(|value| value >= 2))
            && factor != 0
            && self.current_operand_repeat_product > MAX_REPEAT / factor
        {
            return Err(Self::syntax(
                offset,
                "invalid repeat count: nested repetition exceeds 1000",
            ));
        }
        self.current_operand_repeat_product = if factor == 0 {
            0
        } else {
            self.current_operand_repeat_product * factor
        };
        self.expression_repeat_product = self
            .expression_repeat_product
            .max(self.current_operand_repeat_product);
        Ok(())
    }

    fn translate_simple_repetition(&mut self) -> Result<(), GoRegexError> {
        let operator = self.bytes[self.offset];
        if !self.can_repeat {
            return Err(Self::syntax(
                self.offset,
                "missing argument to repetition operator",
            ));
        }
        match (self.repeat_state, operator) {
            (RepeatState::None, _) => {
                self.prepare_repetition();
                self.output.push(char::from(operator));
                if self.repetition_greed_is_inverted() {
                    self.output.push('?');
                }
                self.repeat_state = RepeatState::Quantifier;
            }
            (RepeatState::Quantifier, b'?') => {
                if self.repetition_greed_is_inverted() {
                    debug_assert!(self.output.ends_with('?'));
                    self.output.pop();
                } else {
                    self.output.push('?');
                }
                self.repeat_state = RepeatState::Lazy;
            }
            _ => {
                return Err(Self::syntax(
                    self.offset,
                    "invalid nested repetition operator",
                ));
            }
        }
        self.offset += 1;
        Ok(())
    }

    /// Returns the end-exclusive source range and repetition bounds when the
    /// current brace has Go's exact `{m}`, `{m,}`, or `{m,n}` lexical shape.
    fn repetition(&self) -> Option<(usize, u32, Option<u32>)> {
        let mut cursor = self.offset + 1;
        let minimum_start = cursor;
        while self.bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
            cursor += 1;
        }
        if cursor == minimum_start {
            return None;
        }
        if cursor - minimum_start > 1 && self.bytes[minimum_start] == b'0' {
            return None;
        }
        let minimum = self.source[minimum_start..cursor]
            .parse()
            .unwrap_or(u32::MAX);

        match self.bytes.get(cursor)? {
            b'}' => Some((cursor + 1, minimum, Some(minimum))),
            b',' => {
                cursor += 1;
                let maximum_start = cursor;
                while self.bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
                    cursor += 1;
                }
                if self.bytes.get(cursor) != Some(&b'}') {
                    return None;
                }
                let maximum = if cursor == maximum_start {
                    None
                } else {
                    if cursor - maximum_start > 1 && self.bytes[maximum_start] == b'0' {
                        return None;
                    }
                    Some(
                        self.source[maximum_start..cursor]
                            .parse()
                            .unwrap_or(u32::MAX),
                    )
                };
                Some((cursor + 1, minimum, maximum))
            }
            _ => None,
        }
    }

    fn syntax(offset: usize, message: impl Into<String>) -> GoRegexError {
        GoRegexError::Syntax {
            offset,
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fmt::Write as _;

    use super::{ByteSpan, GoRegex, GoRegexError, NormalizedHaystack, Translator, backend_version};

    fn spans(ranges: &[(usize, usize)]) -> Vec<ByteSpan> {
        ranges
            .iter()
            .map(|&(start, end)| ByteSpan { start, end })
            .collect()
    }

    fn decode_base64(encoded: &str) -> Vec<u8> {
        fn digit(byte: u8) -> u8 {
            match byte {
                b'A'..=b'Z' => byte - b'A',
                b'a'..=b'z' => byte - b'a' + 26,
                b'0'..=b'9' => byte - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                _ => panic!("invalid frozen base64 digit"),
            }
        }

        assert_eq!(encoded.len() % 4, 0, "frozen base64 must be padded");
        let mut decoded = Vec::with_capacity(encoded.len() / 4 * 3);
        for chunk in encoded.as_bytes().chunks_exact(4) {
            let first = digit(chunk[0]);
            let second = digit(chunk[1]);
            decoded.push((first << 2) | (second >> 4));
            if chunk[2] != b'=' {
                let third = digit(chunk[2]);
                decoded.push((second << 4) | (third >> 2));
                if chunk[3] != b'=' {
                    decoded.push((third << 6) | digit(chunk[3]));
                }
            }
        }
        decoded
    }

    fn record_mismatch(
        classes: &mut BTreeMap<&'static str, usize>,
        details: &mut Vec<String>,
        class: &'static str,
        id: &str,
        detail: impl Into<String>,
    ) {
        *classes.entry(class).or_default() += 1;
        if details.len() < 50 {
            details.push(format!("{id}: {class}: {}", detail.into()));
        }
    }

    fn record_match_outcome_mismatch(
        classes: &mut BTreeMap<&'static str, usize>,
        details: &mut Vec<String>,
        approved_divergences: &mut BTreeSet<(String, &'static str)>,
        class: &'static str,
        id: &str,
        outcome: (usize, usize),
        detail: impl Into<String>,
    ) {
        let is_approved_unicode_16_divergence = matches!(
            (id, class, outcome),
            (
                "adversarial/unicode15-u105c0-letter",
                "match-exists" | "match-count",
                (1, 0)
            ) | (
                "adversarial/unicode15-u105c0-not-letter",
                "match-exists" | "match-count",
                (0, 1)
            )
        );
        if is_approved_unicode_16_divergence {
            approved_divergences.insert((id.to_owned(), class));
        } else {
            record_mismatch(classes, details, class, id, detail);
        }
    }

    #[derive(serde::Deserialize)]
    struct CorpusRequest {
        id: String,
        pattern_base64: String,
        input_base64: String,
    }

    #[derive(serde::Deserialize)]
    struct CorpusOutcome {
        id: String,
        compile: CorpusCompile,
        match_exists: bool,
        matches: Vec<CorpusMatch>,
    }

    #[derive(serde::Deserialize)]
    struct CorpusCompile {
        success: bool,
        capture_count: usize,
        capture_names: Vec<String>,
    }

    #[derive(serde::Deserialize)]
    struct CorpusMatch {
        span: [usize; 2],
        captures: Vec<[isize; 2]>,
    }

    fn compare_corpus_match(
        id: &str,
        match_index: usize,
        actual: &super::CaptureSpans,
        expected: &CorpusMatch,
        classes: &mut BTreeMap<&'static str, usize>,
        details: &mut Vec<String>,
    ) {
        let expected_whole = ByteSpan {
            start: expected.span[0],
            end: expected.span[1],
        };
        if actual.whole() != expected_whole {
            record_mismatch(
                classes,
                details,
                "match-span",
                id,
                format!(
                    "match {match_index}: Rust {:?} != Go {expected_whole:?}",
                    actual.whole()
                ),
            );
        }
        if actual.spans().len() != expected.captures.len() {
            record_mismatch(
                classes,
                details,
                "capture-vector-length",
                id,
                format!(
                    "match {match_index}: Rust {} != Go {}",
                    actual.spans().len(),
                    expected.captures.len()
                ),
            );
            return;
        }
        for (capture_index, (actual_capture, pair)) in
            actual.spans().iter().zip(&expected.captures).enumerate()
        {
            let expected_capture = (pair[0] >= 0).then(|| ByteSpan {
                start: usize::try_from(pair[0]).unwrap(),
                end: usize::try_from(pair[1]).unwrap(),
            });
            if *actual_capture != expected_capture {
                record_mismatch(
                    classes,
                    details,
                    "capture-span",
                    id,
                    format!(
                        "match {match_index} capture {capture_index}: Rust {actual_capture:?} != Go {expected_capture:?}"
                    ),
                );
            }
        }
    }

    fn compare_compiled_corpus_case(
        id: &str,
        regex: &GoRegex,
        input: &[u8],
        expected: &CorpusOutcome,
        classes: &mut BTreeMap<&'static str, usize>,
        details: &mut Vec<String>,
        approved_divergences: &mut BTreeSet<(String, &'static str)>,
    ) {
        if regex.capture_count() != expected.compile.capture_count {
            record_mismatch(
                classes,
                details,
                "capture-count",
                id,
                format!(
                    "Rust {} != Go {}",
                    regex.capture_count(),
                    expected.compile.capture_count
                ),
            );
        }
        let actual_names = regex
            .capture_names()
            .iter()
            .map(|name| name.as_deref().unwrap_or(""))
            .collect::<Vec<_>>();
        if actual_names != expected.compile.capture_names {
            record_mismatch(
                classes,
                details,
                "capture-names",
                id,
                format!(
                    "Rust {actual_names:?} != Go {:?}",
                    expected.compile.capture_names
                ),
            );
        }
        if regex.is_match(input) != expected.match_exists {
            record_match_outcome_mismatch(
                classes,
                details,
                approved_divergences,
                "match-exists",
                id,
                (
                    usize::from(regex.is_match(input)),
                    usize::from(expected.match_exists),
                ),
                format!(
                    "Rust {} != Go {}",
                    regex.is_match(input),
                    expected.match_exists
                ),
            );
        }

        let actual_matches = regex.captures_all(input);
        if actual_matches.len() != expected.matches.len() {
            record_match_outcome_mismatch(
                classes,
                details,
                approved_divergences,
                "match-count",
                id,
                (actual_matches.len(), expected.matches.len()),
                format!(
                    "Rust {} != Go {}",
                    actual_matches.len(),
                    expected.matches.len()
                ),
            );
            return;
        }
        for (match_index, (actual, expected_match)) in
            actual_matches.iter().zip(&expected.matches).enumerate()
        {
            compare_corpus_match(id, match_index, actual, expected_match, classes, details);
        }
    }

    #[test]
    fn preserves_source_and_capture_metadata() {
        let source = r"(?P<word>[a-z]+)-(?<1>\d+)-(x)?";
        let regex = GoRegex::compile(source).unwrap();

        assert_eq!(regex.source(), source);
        assert_eq!(regex.capture_count(), 3);
        assert_eq!(
            regex
                .capture_names()
                .iter()
                .map(|name| name.as_deref())
                .collect::<Vec<_>>(),
            vec![None, Some("word"), Some("1"), None]
        );
    }

    #[test]
    fn identifies_the_private_backend_requirements() {
        assert_eq!(
            backend_version(),
            "regex-automata-meta/^0.4.12;regex-syntax/^0.8.5"
        );
    }

    #[test]
    fn reports_whole_and_optional_capture_byte_spans() {
        let regex = GoRegex::compile(r"(?P<key>ab)(?:-(x))?").unwrap();
        let matches = regex.captures_all(b"ab ab-x");

        assert_eq!(matches.len(), 2);
        assert_eq!(
            matches[0].spans(),
            &[
                Some(ByteSpan { start: 0, end: 2 }),
                Some(ByteSpan { start: 0, end: 2 }),
                None,
            ]
        );
        assert_eq!(matches[1].whole(), ByteSpan { start: 3, end: 7 });
        assert_eq!(matches[1].spans()[2], Some(ByteSpan { start: 6, end: 7 }));
    }

    #[test]
    fn returns_all_non_overlapping_and_go_style_empty_matches() {
        let regex = GoRegex::compile("a*").unwrap();
        assert_eq!(regex.find_all(b"baaab"), spans(&[(0, 0), (1, 4), (5, 5)]));
    }

    #[test]
    fn empty_iteration_advances_by_go_utf8_runes() {
        let empty = GoRegex::compile("").unwrap();
        assert_eq!(
            empty.find_all("é中".as_bytes()),
            spans(&[(0, 0), (2, 2), (5, 5)])
        );

        let malformed = [0xFF, 0xE2, 0x82, b'a', 0x80];
        assert_eq!(
            empty.find_all(&malformed),
            spans(&[(0, 0), (1, 1), (2, 2), (3, 3), (4, 4), (5, 5)])
        );
        assert_eq!(
            empty
                .captures_all(&malformed)
                .into_iter()
                .map(|captures| captures.whole())
                .collect::<Vec<_>>(),
            spans(&[(0, 0), (1, 1), (2, 2), (3, 3), (4, 4), (5, 5)])
        );
    }

    #[test]
    fn empty_iteration_suppresses_matches_abutting_non_empty_matches() {
        let regex = GoRegex::compile(r"a+|").unwrap();
        assert_eq!(regex.find_all(b"baa"), spans(&[(0, 0), (1, 3)]));
        assert_eq!(regex.find_all(b"aa"), spans(&[(0, 2)]));
    }

    #[test]
    fn accepts_all_four_literal_brace_patterns() {
        let cases = [
            r#"['"]?\$?{{[^}]+}}['"]?:['"]?\$?{{[^}]+}}['"]?"#,
            r#"import[ \t]+{[ \t\w,]+}[ \t]+from[ \t]+['"][^'"]+['"]"#,
            r"^\$(?:\d+|{\d+})$",
            r"^\${(?:[A-Z_]+|[a-z_]+)}$",
        ];

        for pattern in cases {
            GoRegex::compile(pattern).unwrap_or_else(|error| panic!("{pattern}: {error}"));
        }
        assert!(
            GoRegex::compile(cases[0])
                .unwrap()
                .is_match(br"${{HOST}}:${{PORT}}")
        );
        assert!(
            GoRegex::compile(cases[1])
                .unwrap()
                .is_match(br#"import { name, other } from "pkg""#)
        );
        assert!(GoRegex::compile(cases[2]).unwrap().is_match(b"${12}"));
        assert!(GoRegex::compile(cases[3]).unwrap().is_match(b"${HOME}"));
    }

    #[test]
    fn preserves_real_repetitions_and_rejects_go_oversized_counts() {
        let regex = GoRegex::compile(r"a{2}b{2,}c{1,3}{x}").unwrap();
        assert!(regex.is_match(b"aabbcc{x}"));
        assert_eq!(
            GoRegex::compile(r"a{01}").unwrap().find_all(b"a{01} a"),
            spans(&[(0, 5)])
        );
        assert!(matches!(
            GoRegex::compile("a{1001}"),
            Err(GoRegexError::Syntax { .. })
        ));
        assert!(matches!(
            GoRegex::compile("a{3,2}"),
            Err(GoRegexError::Syntax { .. })
        ));
    }

    #[test]
    fn directives_reset_repeat_nesting_and_apply_adjacent_ungreedy_flags() {
        let cases = [
            ("a*(?i)+", b"aaaA".as_slice()),
            (r"\s*(?i){1,2}", b"  \tA".as_slice()),
            ("$+?(?)?", b"a".as_slice()),
            (r"[\w]*(?){1,2}", b"abc!".as_slice()),
            ("a+(?)*", b"aaa".as_slice()),
            ("a{2}(?){3}", b"aaaaaa".as_slice()),
        ];
        for (pattern, input) in cases {
            GoRegex::compile(pattern)
                .unwrap_or_else(|error| panic!("{pattern}: {error}"))
                .find_all(input);
        }

        assert_eq!(
            GoRegex::compile("a(?U)*a").unwrap().find_all(b"aaa"),
            spans(&[(0, 1), (1, 2), (2, 3)])
        );
        assert_eq!(
            GoRegex::compile("a(?U)+a").unwrap().find_all(b"aaa"),
            spans(&[(0, 2)])
        );
        assert_eq!(
            GoRegex::compile("a(?U){1,2}a").unwrap().find_all(b"aaaa"),
            spans(&[(0, 2), (2, 4)])
        );
        assert_eq!(
            GoRegex::compile("(?U)a(?-U)*a").unwrap().find_all(b"aaa"),
            spans(&[(0, 3)])
        );
    }

    #[test]
    fn enforces_versioned_pattern_and_nesting_limits_at_the_boundary() {
        let at_pattern_limit = "(?)".repeat((super::PATTERN_SIZE_LIMIT - 1) / 3) + "a";
        assert_eq!(at_pattern_limit.len(), super::PATTERN_SIZE_LIMIT);
        assert_eq!(GoRegex::validate(&at_pattern_limit), Ok(0));
        assert!(GoRegex::compile(&at_pattern_limit).unwrap().is_match(b"a"));

        let above_pattern_limit = at_pattern_limit + "a";
        assert_eq!(
            GoRegex::validate(&above_pattern_limit),
            Err(GoRegexError::PatternTooLarge {
                actual: super::PATTERN_SIZE_LIMIT + 1,
                limit: super::PATTERN_SIZE_LIMIT,
            })
        );
        assert!(matches!(
            GoRegex::compile(&above_pattern_limit),
            Err(GoRegexError::PatternTooLarge { .. })
        ));

        let at_nest_limit = "(?:".repeat(super::NEST_LIMIT as usize)
            + "a"
            + &")".repeat(super::NEST_LIMIT as usize);
        assert_eq!(GoRegex::validate(&at_nest_limit), Ok(0));
        assert!(GoRegex::compile(&at_nest_limit).unwrap().is_match(b"a"));

        let above_nest_limit = "(?:".repeat(super::NEST_LIMIT as usize + 1)
            + "a"
            + &")".repeat(super::NEST_LIMIT as usize + 1);
        assert_eq!(
            GoRegex::validate(&above_nest_limit),
            Err(GoRegexError::Backend {
                message: "error parsing regex".into(),
            })
        );
        assert!(matches!(
            GoRegex::compile(&above_nest_limit),
            Err(GoRegexError::Backend { .. })
        ));
    }

    #[test]
    fn enforces_go_nested_repeat_product_limit_before_backend_compilation() {
        assert_eq!(GoRegex::validate(r"(?:a{0,10}){0,100}"), Ok(0));
        assert!(GoRegex::compile(r"(?:a{0,10}){0,100}").is_ok());
        assert_eq!(
            GoRegex::validate(r"(?:a{0,200}){0,200}"),
            GoRegex::compile(r"(?:a{0,200}){0,200}").map(|regex| regex.capture_count())
        );
        assert!(matches!(
            GoRegex::compile(r"(?:a{0,200}){0,200}"),
            Err(GoRegexError::Syntax { offset: 12, .. })
        ));
        assert!(GoRegex::compile(r"(?:a{1000}){0}").is_ok());
    }

    #[test]
    fn bounds_capture_heavy_pikevm_working_sets_before_cache_allocation() {
        let accepted = "()".repeat(512);
        assert_eq!(GoRegex::validate(&accepted), Ok(512));
        let reference = regex_automata::nfa::thompson::pikevm::PikeVM::new(&accepted).unwrap();
        let accepted = GoRegex::compile(&accepted).unwrap();
        let cache = reference.create_cache();
        assert!(super::pikevm_working_size(reference.get_nfa()).unwrap() >= cache.memory_usage());
        assert!(accepted.is_match(b""));

        let rejected = "()".repeat(4_096);
        let error = GoRegex::compile(&rejected).unwrap_err();
        assert_eq!(GoRegex::validate(&rejected), Err(error.clone()));
        let GoRegexError::WorkingSetTooLarge {
            estimated: Some(estimated),
            limit,
        } = error
        else {
            panic!("unexpected compile result: {error:?}");
        };
        assert!(estimated > limit);
        assert_eq!(limit, super::PIKEVM_WORKING_SIZE_LIMIT);
    }

    #[test]
    fn reverse_nfa_limit_keeps_forward_compatible_patterns_searchable() {
        use regex_automata::{Input, meta::Regex, nfa::thompson};

        const LIMIT: usize = 20 << 10;
        GoRegex::preflight(r"\pL", LIMIT)
            .expect("validation accepts the forward NFA before reverse fallback");
        let hir = regex_automata::util::syntax::parse(r"\pL").unwrap();
        thompson::NFA::compiler()
            .configure(thompson::Config::new().nfa_size_limit(Some(LIMIT)))
            .build_from_hir(&hir)
            .expect("the forward Unicode-letter NFA fits the limit");
        let error = Regex::builder()
            .configure(Regex::config().nfa_size_limit(Some(LIMIT)).dfa(false))
            .build_from_hir(&hir)
            .expect_err("the reverse Unicode-letter NFA exceeds the limit");
        assert_eq!(error.size_limit(), Some(LIMIT));

        let backend = GoRegex::build_meta_backend(&hir, LIMIT).unwrap();
        let mut captures = backend.create_captures();
        backend.search_captures(&Input::new("1Ωx"), &mut captures);
        assert_eq!(
            captures.get_group(0),
            Some(regex_automata::Span::from(1..3))
        );
        assert!(backend.is_match("1Ωx"));
        assert!(!backend.is_match("123"));
    }

    #[test]
    fn resource_contract_covers_default_repeat_nesting_and_large_class() {
        // This exercises the upper-bound-shaped inputs in the ordinary debug
        // test profile. Fresh latency measurements are enforced separately by
        // the performance budget gate.
        const SEARCH_BYTES: usize = 1 << 20;

        fn collect_patterns(value: &toml::Value, key: Option<&str>, patterns: &mut Vec<String>) {
            match value {
                toml::Value::Table(table) => {
                    for (child_key, child) in table {
                        collect_patterns(child, Some(child_key), patterns);
                    }
                }
                toml::Value::Array(values) => {
                    for child in values {
                        collect_patterns(child, key, patterns);
                    }
                }
                toml::Value::String(pattern)
                    if matches!(key, Some("regex" | "path" | "regexes" | "paths")) =>
                {
                    patterns.push(pattern.clone());
                }
                _ => {}
            }
        }

        let default: toml::Value = toml::from_str(include_str!("../../default/gitleaks.toml"))
            .expect("embedded default must parse");
        let mut patterns = Vec::new();
        collect_patterns(&default, None, &mut patterns);
        let longest_default = patterns
            .iter()
            .max_by_key(|pattern| pattern.len())
            .expect("default contains regex patterns");
        assert_eq!(longest_default.len(), 931);

        let repeat_1000 = GoRegex::compile("a{1000}").unwrap();
        let deep = "(?:".repeat(super::NEST_LIMIT as usize)
            + "a"
            + &")".repeat(super::NEST_LIMIT as usize);
        let deep = GoRegex::compile(&deep).unwrap();
        let mut class = String::from("[");
        for rune in 1..=1_000 {
            let _ = write!(class, r"\x{{{rune:X}}}");
        }
        class.push(']');
        let large_class = GoRegex::compile(&class).unwrap();
        let longest_default = GoRegex::compile(longest_default).unwrap();

        assert!(repeat_1000.is_match(&vec![b'a'; 1_000]));
        assert!(deep.is_match(b"a"));
        assert!(large_class.is_match("Ω".as_bytes()));
        assert!(!longest_default.is_match(&vec![b'x'; SEARCH_BYTES]));
    }

    #[test]
    fn perl_classes_and_boundaries_are_ascii_in_and_out_of_classes() {
        let digit = GoRegex::compile(r"\d+").unwrap();
        assert!(digit.is_match(b"123"));
        assert!(!digit.is_match("१२३".as_bytes()));

        let word_class = GoRegex::compile(r"[\w]+").unwrap();
        assert!(word_class.is_match(b"az_AZ09"));
        assert!(!word_class.is_match("café".as_bytes()[3..].as_ref()));

        let boundary = GoRegex::compile(r"\bword\b").unwrap();
        assert!(boundary.is_match("éword!".as_bytes()));
        assert!(!boundary.is_match(b"swordfish"));
    }

    #[test]
    fn negated_ascii_classes_consume_unicode_runes_and_malformed_bytes() {
        let regex = GoRegex::compile(r"\W").unwrap();
        assert_eq!(regex.find_all("é".as_bytes()), spans(&[(0, 2)]));
        assert_eq!(regex.find_all(b"\xff"), spans(&[(0, 1)]));

        let class = GoRegex::compile(r"[^\w]").unwrap();
        assert_eq!(class.find_all("é".as_bytes()), spans(&[(0, 2)]));
        assert_eq!(class.find_all(b"\xfe"), spans(&[(0, 1)]));

        let complement = GoRegex::compile(r"[\D]").unwrap();
        assert_eq!(complement.find_all("é".as_bytes()), spans(&[(0, 2)]));
        assert_eq!(complement.find_all(b"\xfd"), spans(&[(0, 1)]));

        let double_complement = GoRegex::compile(r"[^\D]").unwrap();
        assert!(double_complement.is_match(b"7"));
        assert!(!double_complement.is_match("é".as_bytes()));
        assert!(!double_complement.is_match(b"\xfc"));
    }

    #[test]
    fn go_class_literals_do_not_become_rust_class_algebra() {
        let intersection = GoRegex::compile(r"[a&&b]+").unwrap();
        assert_eq!(intersection.find_all(b"a&b"), spans(&[(0, 3)]));

        let symmetric_difference = GoRegex::compile(r"[a~~b]+").unwrap();
        assert_eq!(symmetric_difference.find_all(b"a~b"), spans(&[(0, 3)]));

        assert!(GoRegex::compile(r"[a-c]+").unwrap().is_match(b"abc"));
        assert!(matches!(
            GoRegex::compile(r"[a--b]"),
            Err(GoRegexError::Syntax { .. })
        ));
    }

    #[test]
    fn unicode_properties_are_gated_to_the_go_namespace() {
        for pattern in [
            r"\p{Greek}+",
            r"\p{Uppercase_Letter}",
            r"\p{upper case-let ter}",
            r"\p{Any}",
            r"\p{Assigned}",
            r"\p{ASCII}",
            r"\p{LC}",
            r"\p{^Greek}",
            r"[\P{Greek}]",
        ] {
            GoRegex::compile(pattern).unwrap_or_else(|error| panic!("{pattern}: {error}"));
        }

        for pattern in [
            r"\p{Age:3.0}",
            r"\p{Alphabetic}",
            r"\p{Script=Greek}",
            r"\p{Emoji}",
            r"\p{Old_Italic}",
            r"\p{OldItalic}",
            r"[\p{Age:3.0}]",
        ] {
            assert!(
                matches!(GoRegex::compile(pattern), Err(GoRegexError::Syntax { .. })),
                "{pattern}"
            );
        }
    }

    #[test]
    fn surrogate_properties_use_go_operational_semantics() {
        for pattern in [r"\p{Cs}", r"\p{Surrogate}", r"[\p{Cs}]"] {
            let regex = GoRegex::compile(pattern).unwrap();
            assert!(!regex.is_match(b"a"), "{pattern}");
            assert!(!regex.is_match("é".as_bytes()), "{pattern}");
            assert!(!regex.is_match(b"\xff"), "{pattern}");
        }

        for pattern in [r"\P{Cs}", r"\P{Surrogate}", r"[\P{Cs}]"] {
            let regex = GoRegex::compile(pattern).unwrap();
            assert_eq!(
                regex.find_all("aé".as_bytes()),
                spans(&[(0, 1), (1, 3)]),
                "{pattern}"
            );
            assert_eq!(regex.find_all(b"\xff"), spans(&[(0, 1)]), "{pattern}");
        }

        let mixed = GoRegex::compile(r"[a\p{Cs}]").unwrap();
        assert!(mixed.is_match(b"a"));
        assert!(!mixed.is_match(b"b"));

        let spanning = Translator::new(r"[^\x{D7FF}-\x{E000}]")
            .translate()
            .unwrap();
        assert_eq!(spanning.pattern, r"[^\x{D7FF}-\x{E000}]");
        assert!(
            GoRegex::compile(r"\x{D7FF}")
                .unwrap()
                .is_match("\u{D7FF}".as_bytes())
        );
        assert!(
            GoRegex::compile(r"\x{E000}")
                .unwrap()
                .is_match("\u{E000}".as_bytes())
        );
        assert!(
            GoRegex::compile(r"[\x{D7FF}\x{E000}]")
                .unwrap()
                .is_match("\u{D7FF}\u{E000}".as_bytes())
        );
        assert!(
            !GoRegex::compile(r"[^\x{D7FF}]")
                .unwrap()
                .is_match("\u{D7FF}".as_bytes())
        );
        assert!(
            !GoRegex::compile(r"[^\x{E000}]")
                .unwrap()
                .is_match("\u{E000}".as_bytes())
        );
        let spanning = GoRegex::compile(r"[^\x{D7FF}-\x{E000}]").unwrap();
        assert_eq!(
            spanning.find_all("A\u{D7FF}\u{E000}".as_bytes()),
            spans(&[(0, 1)])
        );
    }

    #[test]
    fn dot_consumes_one_unicode_rune_or_one_malformed_byte() {
        let regex = GoRegex::compile(".").unwrap();
        let input = [b'a', 0xC3, 0xA9, 0xFF, b'z'];
        assert_eq!(
            regex.find_all(&input),
            spans(&[(0, 1), (1, 3), (3, 4), (4, 5)])
        );
        assert!(!regex.is_match(b"\n"));
        assert!(GoRegex::compile("(?s:.)").unwrap().is_match(b"\n"));
    }

    #[test]
    fn malformed_bytes_are_normalized_to_individual_rune_errors() {
        let literal = GoRegex::compile("\u{fffd}").unwrap();
        let escaped = GoRegex::compile(r"\x{FFFD}").unwrap();
        let malformed = [0xFF, 0xC0, 0x80, 0xE2, 0x82];
        let expected = spans(&[(0, 1), (1, 2), (2, 3), (3, 4), (4, 5)]);

        assert_eq!(literal.find_all(&malformed), expected);
        assert_eq!(escaped.find_all(&malformed), expected);
        assert!(!escaped.is_match("é".as_bytes()));
        assert!(matches!(
            NormalizedHaystack::new("é".as_bytes()).bytes,
            std::borrow::Cow::Borrowed(_)
        ));
    }

    #[test]
    fn sparse_normalization_preserves_replacement_interiors_and_literal_rune_errors() {
        let input = b"\xef\xbf\xbd\xffA\xe2\x82";
        let normalized = NormalizedHaystack::new(input);
        // The first RuneError is valid source UTF-8. Only the three invalid
        // source bytes expand, including each byte of the truncated tail.
        assert_eq!(
            normalized.bytes(),
            "\u{fffd}\u{fffd}A\u{fffd}\u{fffd}".as_bytes()
        );
        assert_eq!(normalized.replacement_starts, [3, 7, 10]);
        let expected = [0, 1, 2, 3, 3, 3, 4, 5, 5, 5, 6, 6, 6, 7];
        for (offset, original) in expected.into_iter().enumerate().rev() {
            assert_eq!(
                normalized.original_span(ByteSpan {
                    start: offset,
                    end: offset
                }),
                ByteSpan {
                    start: original,
                    end: original
                },
                "normalized boundary {offset}",
            );
        }
    }

    #[test]
    fn sparse_normalization_matches_every_boundary_of_short_byte_inputs() {
        assert_normalization_matches_per_byte_reference(b"");
        for first in 0..=u8::MAX {
            assert_normalization_matches_per_byte_reference(&[first]);
            for second in 0..=u8::MAX {
                assert_normalization_matches_per_byte_reference(&[first, second]);
            }
        }
        for input in [
            "éΩ日本語\u{fffd}😀".as_bytes(),
            b"\xff\xc3\xa9\x80\xe2\x82\xac\xff\xf0\x9f\x98\x80\xff",
            b"\xf0\x90\x80A\xed\xa0\x80\xe0\x80\x80\xc0\xaf",
            b"\xe2\x82",
            b"\xf0\x9f\x98",
            b"\xf4\x8f\xbf\xbf\xff\xf4\x90\x80\x80",
        ] {
            assert_normalization_matches_per_byte_reference(input);
        }
        // Cover late expansion and a long run of adjacent replacements without
        // putting the multi-megabyte performance fixtures in ordinary tests.
        let mut late_invalid = vec![b'a'; 4_096];
        late_invalid.push(0xff);
        assert_normalization_matches_per_byte_reference(&late_invalid);
        assert_normalization_matches_per_byte_reference(&[0xff; 4_096]);
    }

    fn assert_normalization_matches_per_byte_reference(input: &[u8]) {
        let (expected_bytes, expected_boundaries) = per_byte_normalization(input);
        let normalized = NormalizedHaystack::new(input);
        assert_eq!(normalized.bytes(), expected_bytes);
        let mut cursor = 0;
        for (offset, &original) in expected_boundaries.iter().enumerate() {
            assert_eq!(
                normalized.original_span_in_order(
                    ByteSpan {
                        start: offset,
                        end: offset
                    },
                    &mut cursor,
                ),
                ByteSpan {
                    start: original,
                    end: original
                },
            );
        }
        assert_eq!(
            normalized.original_span_in_order(
                ByteSpan {
                    start: 0,
                    end: expected_bytes.len()
                },
                &mut 0,
            ),
            ByteSpan {
                start: 0,
                end: input.len()
            },
        );
        // Reverse traversal also exercises arbitrary endpoint order, as used
        // by capture groups. No shared monotonic cursor may affect mapping.
        for (offset, original) in expected_boundaries.into_iter().enumerate().rev() {
            assert_eq!(
                normalized.original_span(ByteSpan {
                    start: offset,
                    end: offset
                }),
                ByteSpan {
                    start: original,
                    end: original
                },
                "normalized boundary {offset}, input length {}",
                input.len(),
            );
        }
    }

    // Frozen former per-byte normalization and mapping. Keep it independent
    // of UTF-8 chunks and sparse checkpoints used by the production path.
    fn per_byte_normalization(original: &[u8]) -> (Vec<u8>, Vec<usize>) {
        let mut bytes = Vec::with_capacity(original.len());
        let mut boundaries = Vec::with_capacity(original.len() + 1);
        boundaries.push(0);
        let mut offset = 0;
        while offset < original.len() {
            let width = super::utf8_rune_width(&original[offset..]);
            if width > 1 || original[offset].is_ascii() {
                bytes.extend_from_slice(&original[offset..offset + width]);
                boundaries.extend((1..=width).map(|step| offset + step));
                offset += width;
            } else {
                bytes.extend_from_slice("\u{fffd}".as_bytes());
                boundaries.extend([offset, offset, offset + 1]);
                offset += 1;
            }
        }
        (bytes, boundaries)
    }

    #[test]
    fn classes_and_captures_remap_normalized_runes_to_original_bytes() {
        let input = [0xC3, 0xA9, b'-', 0xFF];
        let class = GoRegex::compile(r"[^a-]").unwrap();
        assert_eq!(class.find_all(&input), spans(&[(0, 2), (3, 4)]));

        let captures = GoRegex::compile(r"(.)-(\x{FFFD})")
            .unwrap()
            .captures_all(&input);
        assert_eq!(captures.len(), 1);
        assert_eq!(
            captures[0].spans(),
            &[
                Some(ByteSpan { start: 0, end: 4 }),
                Some(ByteSpan { start: 0, end: 2 }),
                Some(ByteSpan { start: 3, end: 4 }),
            ]
        );
    }

    #[test]
    fn unicode_properties_use_the_compatible_backend_tables() {
        assert!(
            GoRegex::compile(r"\pL")
                .unwrap()
                .is_match("\u{105c0}".as_bytes())
        );
        assert!(matches!(
            GoRegex::compile(r"\p{Todhri}"),
            Err(GoRegexError::Syntax { .. })
        ));
    }

    #[test]
    fn dollar_is_absolute_unless_multiline_is_active() {
        assert!(!GoRegex::compile("x$").unwrap().is_match(b"x\n"));
        assert!(GoRegex::compile("(?m:x$)").unwrap().is_match(b"x\ny"));
        assert!(GoRegex::compile("(?m)x$").unwrap().is_match(b"x\ny"));
        assert!(!GoRegex::compile("(?m)x(?-m:$)").unwrap().is_match(b"x\ny"));
    }

    #[test]
    fn supports_posix_classes_anchors_quoting_and_octal() {
        let regex = GoRegex::compile(r"\A[[:alpha:]]+\Q.{}\E\040\z").unwrap();
        assert!(regex.is_match(b"Ascii.{} "));
        assert!(!regex.is_match("é.{} ".as_bytes()));
        assert!(
            GoRegex::compile(r"\0[\12]\123")
                .unwrap()
                .is_match(&[0, b'\n', 0o123])
        );

        let unicode = GoRegex::compile(r"\p{Greek}+\x{20}\pL+").unwrap();
        assert!(unicode.is_match("Ω α".as_bytes()));
        assert_eq!(
            GoRegex::compile(r"\P{Greek}").unwrap().find_all(b"\xff"),
            spans(&[(0, 1)])
        );
        assert_eq!(
            GoRegex::compile(r"[\p{So}]").unwrap().find_all(b"\xfe"),
            spans(&[(0, 1)])
        );
        assert_eq!(
            GoRegex::compile(r"\x{FFFD}").unwrap().find_all(b"\xff"),
            spans(&[(0, 1)])
        );
    }

    #[test]
    fn compiles_formerly_default_size_limited_patterns() {
        let patterns = [
            r#"(?i)[\w.-]{0,50}?(?:access|auth|(?-i:[Aa]pi|API)|credential|creds|key|passw(?:or)?d|secret|token)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([\w.=-]{10,150}|[a-z0-9][a-z0-9+/]{11,}={0,3})(?:[\x60'"\s;]|\\[nr]|$)"#,
            r"pypi-AgEIcHlwaS5vcmc[\w-]{50,1000}",
            r#"\b(hvb\.[\w-]{138,300})(?:[\x60'"\s;]|\\[nr]|$)"#,
        ];

        for pattern in patterns {
            GoRegex::compile(pattern).unwrap_or_else(|error| panic!("{pattern}: {error}"));
        }
    }

    #[test]
    fn compiles_every_pattern_in_the_shipped_default() {
        fn compile_string(value: &toml::Value, context: &str, count: &mut usize) {
            let Some(pattern) = value.as_str() else {
                return;
            };
            GoRegex::compile(pattern)
                .unwrap_or_else(|error| panic!("default {context} `{pattern}`: {error}"));
            *count += 1;
        }

        fn compile_list(table: &toml::value::Table, key: &str, context: &str, count: &mut usize) {
            if let Some(values) = table.get(key).and_then(toml::Value::as_array) {
                for value in values {
                    compile_string(value, context, count);
                }
            }
        }

        fn compile_allowlist(value: &toml::Value, context: &str, count: &mut usize) {
            let table = value.as_table().expect("allowlist must be a table");
            compile_list(table, "paths", context, count);
            compile_list(table, "regexes", context, count);
        }

        let root: toml::Value = toml::from_str(include_str!("../../default/gitleaks.toml"))
            .expect("embedded default must parse");
        let root = root.as_table().expect("embedded default must be a table");
        let mut count = 0;

        compile_allowlist(&root["allowlist"], "global allowlist", &mut count);
        for (rule_index, rule) in root["rules"]
            .as_array()
            .expect("rules must be an array")
            .iter()
            .enumerate()
        {
            let table = rule.as_table().expect("rule must be a table");
            for field in ["regex", "path"] {
                if let Some(value) = table.get(field) {
                    compile_string(value, &format!("rule {rule_index} {field}"), &mut count);
                }
            }
            if let Some(allowlists) = table.get("allowlists").and_then(toml::Value::as_array) {
                for (allowlist_index, allowlist) in allowlists.iter().enumerate() {
                    compile_allowlist(
                        allowlist,
                        &format!("rule {rule_index} allowlist {allowlist_index}"),
                        &mut count,
                    );
                }
            }
        }

        assert!(count > 300, "expected the complete shipped pattern set");
    }

    #[test]
    fn canonical_go_regex_corpus_matches_except_approved_unicode_16_edges() {
        const MANIFEST: &str = include_str!("../../../../compat/regex-corpus/manifest-v1.json");
        const REQUESTS: &str = include_str!("../../../../compat/regex-corpus/requests-v1.jsonl");
        const OUTCOMES: &str = include_str!("../../../../compat/regex-corpus/outcomes-v1.jsonl");

        let manifest: serde_json::Value = serde_json::from_str(MANIFEST).unwrap();
        let request_count = usize::try_from(manifest["request_count"].as_u64().unwrap()).unwrap();
        let compile_error_count =
            usize::try_from(manifest["compile_error_count"].as_u64().unwrap()).unwrap();
        let requests = REQUESTS.lines().collect::<Vec<_>>();
        let outcomes = OUTCOMES.lines().collect::<Vec<_>>();
        assert_eq!(requests.len(), request_count);
        assert_eq!(outcomes.len(), requests.len());

        let mut classes = BTreeMap::new();
        let mut details = Vec::new();
        let mut approved_divergences = BTreeSet::new();
        let mut expected_compile_failures = 0;

        for (request_line, outcome_line) in requests.into_iter().zip(outcomes) {
            let request: CorpusRequest = serde_json::from_str(request_line).unwrap();
            let outcome: CorpusOutcome = serde_json::from_str(outcome_line).unwrap();
            assert_eq!(outcome.id, request.id);

            let pattern_bytes = decode_base64(&request.pattern_base64);
            let input = decode_base64(&request.input_base64);
            if !outcome.compile.success {
                expected_compile_failures += 1;
            }
            let compiled = std::str::from_utf8(&pattern_bytes)
                .map_err(|error| error.to_string())
                .and_then(|pattern| GoRegex::compile(pattern).map_err(|error| error.to_string()));

            let Ok(regex) = compiled else {
                if outcome.compile.success {
                    record_mismatch(
                        &mut classes,
                        &mut details,
                        "unexpected-compile-failure",
                        &request.id,
                        "Go compiled successfully",
                    );
                }
                continue;
            };
            if !outcome.compile.success {
                record_mismatch(
                    &mut classes,
                    &mut details,
                    "unexpected-compile-success",
                    &request.id,
                    "Go rejected the pattern",
                );
                continue;
            }
            compare_compiled_corpus_case(
                &request.id,
                &regex,
                &input,
                &outcome,
                &mut classes,
                &mut details,
                &mut approved_divergences,
            );
        }

        assert_eq!(expected_compile_failures, compile_error_count);
        let expected_divergences = BTreeSet::from([
            (
                "adversarial/unicode15-u105c0-letter".to_owned(),
                "match-count",
            ),
            (
                "adversarial/unicode15-u105c0-letter".to_owned(),
                "match-exists",
            ),
            (
                "adversarial/unicode15-u105c0-not-letter".to_owned(),
                "match-count",
            ),
            (
                "adversarial/unicode15-u105c0-not-letter".to_owned(),
                "match-exists",
            ),
        ]);
        assert_eq!(approved_divergences, expected_divergences);
        assert!(
            classes.is_empty(),
            "GoRegex corpus mismatches by class: {classes:?}\n{}",
            details.join("\n")
        );
    }

    #[test]
    fn malformed_patterns_are_fallible() {
        for pattern in [
            "(", "[abc", r"\1", r"\8", r"\u1234", "a++", "(?x:a)", "a{1001}",
        ] {
            assert!(GoRegex::compile(pattern).is_err(), "{pattern}");
        }
    }

    #[test]
    fn reused_capture_scratch_never_exposes_an_earlier_search() {
        let span = |start, end| Some(ByteSpan { start, end });
        let regex = GoRegex::compile("(a)|(b)").unwrap();
        let mut scratch = regex.capture_scratch();
        for (haystack, expected) in [
            (b"a".as_slice(), Some(vec![span(0, 1), span(0, 1), None])),
            (b"b".as_slice(), Some(vec![span(0, 1), None, span(0, 1)])),
            (b"zzz".as_slice(), None),
            (b"".as_slice(), None),
            (b"za".as_slice(), Some(vec![span(1, 2), span(1, 2), None])),
            (
                b"\xffb".as_slice(),
                Some(vec![span(1, 2), None, span(1, 2)]),
            ),
        ] {
            assert_eq!(
                regex
                    .captures_into(haystack, &mut scratch)
                    .map(<[_]>::to_vec),
                expected,
                "{haystack:?}",
            );
        }
    }

    // Frozen allocation-per-call search, retained only as differential evidence.
    fn frozen_captures(regex: &GoRegex, haystack: &[u8]) -> Option<Vec<Option<ByteSpan>>> {
        let normalized = NormalizedHaystack::new(haystack);
        let mut captures = regex.backend.create_captures();
        regex.backend.search_captures(
            &regex_automata::Input::new(normalized.bytes()),
            &mut captures,
        );
        captures.get_group(0)?;
        Some(
            (0..regex.capture_names.len())
                .map(|index| {
                    captures
                        .get_group(index)
                        .map(|span| normalized.original_span(ByteSpan::from_span(span)))
                })
                .collect(),
        )
    }

    #[test]
    fn reused_capture_scratch_resets_long_pikevm_captures() {
        // The Unicode classes make the NFA large enough that these match spans
        // exceed the bounded backtracker's limit. The expression is not
        // one-pass, so capture resolution reaches the PikeVM's slot handling.
        let long_a = vec![b'a'; 1 << 14];
        let long_b = vec![b'1'; 1 << 14];
        let length = long_a.len();
        let span = |start, end| Some(ByteSpan { start, end });
        let regex = GoRegex::compile(r"(\p{L}+?)(\p{L}*)|(\p{N}+)").unwrap();
        let mut scratch = regex.capture_scratch();
        for (haystack, expected) in [
            (
                long_a.as_slice(),
                Some(vec![span(0, length), span(0, 1), span(1, length), None]),
            ),
            (b"--".as_slice(), None),
            (
                long_b.as_slice(),
                Some(vec![span(0, length), None, None, span(0, length)]),
            ),
            (
                long_a.as_slice(),
                Some(vec![span(0, length), span(0, 1), span(1, length), None]),
            ),
        ] {
            assert_eq!(frozen_captures(&regex, haystack), expected);
            assert_eq!(
                regex
                    .captures_into(haystack, &mut scratch)
                    .map(<[_]>::to_vec),
                expected,
            );
        }
    }

    #[test]
    fn reused_capture_scratch_matches_the_frozen_fresh_search() {
        let haystacks: &[&[u8]] = &[
            b"a",
            b"b",
            b"ab",
            b"zzz",
            b"",
            b"c",
            b"bc",
            b"ac",
            b"abc",
            b"xfooy",
            b"xfoo",
            b"\xffa",
            b"\xc3\xa9b",
            b"\xe2\x82",
        ];
        for pattern in [
            "(a)|(b)",
            "^(a)|^(b)",
            "(a+)|(b+)",
            "(?P<x>a)?(?P<y>b)?c",
            r"x(\w+?)(y)?$",
            "()a",
        ] {
            let regex = GoRegex::compile(pattern).unwrap();
            let mut scratch = regex.capture_scratch();
            for haystack in haystacks
                .iter()
                .chain(haystacks.iter().rev())
                .chain(haystacks.iter())
            {
                let expected = frozen_captures(&regex, haystack);
                assert_eq!(
                    regex
                        .captures_into(haystack, &mut scratch)
                        .map(<[_]>::to_vec),
                    expected,
                    "pattern {pattern}, haystack {haystack:?}",
                );
                assert_eq!(
                    regex.captures(haystack).map(|found| found.spans),
                    expected,
                    "pattern {pattern}, haystack {haystack:?}",
                );
            }
        }
    }

    #[test]
    fn wrapper_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<GoRegex>();
    }
}
