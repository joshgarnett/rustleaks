//! Private encoded-segment decoder and original-offset mapper.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::ops::Range;
use std::sync::{Arc, OnceLock};

use base64::Engine as _;
use base64::alphabet;
use base64::engine::{DecodePaddingMode, general_purpose};

use crate::regex::GoRegex;

const ENCODINGS_PATTERN: &str = concat!(
    "(?P<percent>%[0-9A-Fa-f]{2}(?:.*%[0-9A-Fa-f]{2})?)|",
    r"(?P<unicode>(?:(?:U\+[a-fA-F0-9]{4}(?:\s|$))+|(?i)(?:\\{1,2}u[a-fA-F0-9]{4})+))|",
    "(?P<hex>[0-9A-Fa-f]{32,})|",
    r"(?P<base64>[\w\/+-]{16,}={0,2})",
);
const GO_STANDARD_BASE64: general_purpose::GeneralPurpose = general_purpose::GeneralPurpose::new(
    &alphabet::STANDARD,
    general_purpose::GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
);
const GO_RAW_URL_BASE64: general_purpose::GeneralPurpose = general_purpose::GeneralPurpose::new(
    &alphabet::URL_SAFE,
    general_purpose::GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::RequireNone),
);
static ENCODINGS_REGEX: OnceLock<GoRegex> = OnceLock::new();

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct StartEnd {
    pub(crate) start: isize,
    pub(crate) end: isize,
}

impl StartEnd {
    fn overlaps(self, other: Self) -> bool {
        other.start <= self.end && other.end >= self.start
    }

    fn contains(self, other: Self) -> bool {
        self.start <= other.start && other.end <= self.end
    }

    fn add(self, other: Self) -> Self {
        Self {
            start: self.start + other.start,
            end: self.end + other.end,
        }
    }

    fn sub(self, other: Self) -> Self {
        Self {
            start: self.start - other.start,
            end: self.end - other.end,
        }
    }

    fn merge(self, other: Self) -> Self {
        Self {
            start: self.start.min(other.start),
            end: self.end.max(other.end),
        }
    }

    fn overflow(self, other: Self) -> Self {
        self.merge(other).sub(self)
    }

    fn as_usize(self) -> Option<std::ops::Range<usize>> {
        Some(usize::try_from(self.start).ok()?..usize::try_from(self.end).ok()?)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Encoding {
    Percent,
    Unicode,
    Hex,
    Base64,
}

impl Encoding {
    const ALL: [Self; 4] = [Self::Percent, Self::Unicode, Self::Hex, Self::Base64];

    const fn bit(self) -> u8 {
        match self {
            Self::Percent => 1,
            Self::Unicode => 2,
            Self::Hex => 4,
            Self::Base64 => 8,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Percent => "percent",
            Self::Unicode => "unicode",
            Self::Hex => "hex",
            Self::Base64 => "base64",
        }
    }

    const fn precedence(self) -> u8 {
        match self {
            Self::Percent => 4,
            Self::Unicode => 3,
            Self::Hex => 2,
            Self::Base64 => 1,
        }
    }

    /// Appends the decoded form of `encoded` to `output`, or leaves `output`
    /// unchanged when `encoded` does not decode to a value.
    fn append_decoded(self, encoded: &[u8], output: &mut Vec<u8>) {
        match self {
            Self::Percent => append_percent(encoded, output),
            Self::Unicode => append_unicode(encoded, output),
            Self::Hex => append_hex(encoded, output),
            Self::Base64 => append_base64(encoded, output),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EncodingMatch {
    encoding: Encoding,
    range: StartEnd,
}

/// Offsets of the line bounds that [`current_line`] reports for one segment,
/// recorded once per decode pass against that pass's output.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct LineBounds {
    /// Last newline at or before the decoded start, or zero.
    start: usize,
    /// First newline at or after the decoded end, or the output length.
    end: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EncodedSegment {
    predecessors: Arc<[Self]>,
    original: StartEnd,
    encoded: StartEnd,
    decoded: StartEnd,
    decoded_value: Arc<[u8]>,
    encodings: u8,
    depth: usize,
    line: LineBounds,
}

impl EncodedSegment {
    pub(crate) const fn original(&self) -> StartEnd {
        self.original
    }

    pub(crate) const fn encoded(&self) -> StartEnd {
        self.encoded
    }

    pub(crate) const fn decoded(&self) -> StartEnd {
        self.decoded
    }

    pub(crate) fn decoded_value(&self) -> &[u8] {
        &self.decoded_value
    }

    pub(crate) const fn depth(&self) -> usize {
        self.depth
    }
}

#[derive(Debug)]
pub(crate) struct Decoder {
    decoded: BTreeMap<Vec<u8>, Arc<[u8]>>,
    encodings: &'static GoRegex,
}

impl Decoder {
    pub(crate) fn new() -> Self {
        Self {
            decoded: BTreeMap::new(),
            encodings: ENCODINGS_REGEX.get_or_init(|| {
                GoRegex::compile(ENCODINGS_PATTERN)
                    .expect("the static encoding expression must compile")
            }),
        }
    }

    /// Decodes one pass, returning the complete output even when nothing
    /// decoded. Production scans use [`Self::decode_controlled`].
    pub(crate) fn decode(
        &mut self,
        data: &[u8],
        predecessors: &[EncodedSegment],
    ) -> (Vec<u8>, Vec<EncodedSegment>) {
        let (output, segments) =
            match self.decode_controlled(data, predecessors, || Ok::<(), Infallible>(())) {
                Ok(decoded) => decoded,
                Err(never) => match never {},
            };
        if segments.is_empty() {
            (data.to_vec(), segments)
        } else {
            (output, segments)
        }
    }

    /// Decodes one pass under the caller's checkpoint.
    ///
    /// When no segment decodes the returned buffer is empty and unallocated:
    /// the caller retains `data` and only reads the buffer once `segments` is
    /// non-empty.
    pub(crate) fn decode_controlled<E>(
        &mut self,
        data: &[u8],
        predecessors: &[EncodedSegment],
        mut checkpoint: impl FnMut() -> Result<(), E>,
    ) -> Result<(Vec<u8>, Vec<EncodedSegment>), E> {
        let (output, mut segments) =
            self.find_encoded_segments(data, predecessors, &mut checkpoint)?;
        if segments.is_empty() {
            return Ok((output, segments));
        }

        // The output was assembled alongside the candidates; these are the
        // per-segment assembly checkpoints.
        for _ in &segments {
            checkpoint()?;
        }
        debug_assert!(segments_are_ordered_and_disjoint(&segments));
        record_line_bounds(&mut segments, &output);
        Ok((output, segments))
    }

    /// Decodes every candidate into segments and the pass output.
    ///
    /// Decoded values always reach the cache and the segment as `Arc<[u8]>`.
    /// Before the first accepted segment a miss decodes into `scratch` so a
    /// pass that decodes nothing never copies `data`. After that a miss
    /// decodes straight into `output`, since the bytes between candidates are
    /// needed regardless of whether the candidate is accepted.
    fn find_encoded_segments<E>(
        &mut self,
        data: &[u8],
        predecessors: &[EncodedSegment],
        checkpoint: &mut impl FnMut() -> Result<(), E>,
    ) -> Result<(Vec<u8>, Vec<EncodedSegment>), E> {
        if data.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }

        let predecessor_depth = predecessors.first().map_or(0, |segment| segment.depth);
        let predecessor_snapshot: Arc<[EncodedSegment]> = Arc::from(predecessors);
        let mut decoded_shift = 0isize;
        let mut segments = Vec::new();
        let mut output = Vec::new();
        let mut scratch = Vec::new();
        // Bytes of `data` already represented in `output`.
        let mut copied_to = 0;
        for candidate in self.find_encoding_matches(data, checkpoint)? {
            checkpoint()?;
            let Some(encoded_range) = candidate.range.as_usize() else {
                continue;
            };
            let encoded_value = &data[encoded_range.clone()];
            let (decoded_value, decoded_in_output): (Arc<[u8]>, bool) =
                match self.decoded.get(encoded_value) {
                    Some(cached) => (Arc::clone(cached), false),
                    None => {
                        let in_output = !segments.is_empty();
                        let value: Arc<[u8]> = if in_output {
                            output.extend_from_slice(&data[copied_to..encoded_range.start]);
                            copied_to = encoded_range.start;
                            let value_start = output.len();
                            candidate
                                .encoding
                                .append_decoded(encoded_value, &mut output);
                            Arc::from(&output[value_start..])
                        } else {
                            scratch.clear();
                            candidate
                                .encoding
                                .append_decoded(encoded_value, &mut scratch);
                            Arc::from(scratch.as_slice())
                        };
                        self.decoded
                            .insert(encoded_value.to_vec(), Arc::clone(&value));
                        (value, in_output)
                    }
                };
            if decoded_value.is_empty() {
                continue;
            }

            let decoded_start = candidate.range.start + decoded_shift;
            let decoded_end = decoded_start + isize::try_from(decoded_value.len()).unwrap();
            let mut encodings = candidate.encoding.bit();
            if !predecessors.is_empty() {
                for predecessor in predecessors {
                    checkpoint()?;
                    if candidate.range.overlaps(predecessor.decoded) {
                        encodings |= predecessor.encodings;
                    }
                }
            }
            if !decoded_in_output {
                if segments.is_empty() {
                    output.reserve(data.len());
                }
                output.extend_from_slice(&data[copied_to..encoded_range.start]);
                output.extend_from_slice(&decoded_value);
            }
            copied_to = encoded_range.end;
            segments.push(EncodedSegment {
                predecessors: Arc::clone(&predecessor_snapshot),
                original: to_original(predecessors, candidate.range),
                encoded: candidate.range,
                decoded: StartEnd {
                    start: decoded_start,
                    end: decoded_end,
                },
                decoded_value: Arc::clone(&decoded_value),
                encodings,
                depth: predecessor_depth + 1,
                line: LineBounds::default(),
            });
            decoded_shift += isize::try_from(decoded_value.len()).unwrap()
                - isize::try_from(encoded_value.len()).unwrap();
        }
        if !segments.is_empty() {
            output.extend_from_slice(&data[copied_to..]);
        }
        Ok((output, segments))
    }

    /// Returns every encoding-regex match in order, one entry per match.
    fn encoding_candidates<E>(
        &self,
        data: &[u8],
        checkpoint: &mut impl FnMut() -> Result<(), E>,
    ) -> Result<Vec<EncodingMatch>, E> {
        let spans = self.encodings.find_all(data);
        let mut all = Vec::with_capacity(spans.len());
        for span in spans {
            checkpoint()?;
            all.push(EncodingMatch {
                encoding: classify_encoding_span(&data[span.start..span.end]),
                range: StartEnd {
                    start: isize::try_from(span.start).unwrap(),
                    end: isize::try_from(span.end).unwrap(),
                },
            });
        }
        Ok(all)
    }

    fn find_encoding_matches<E>(
        &self,
        data: &[u8],
        checkpoint: &mut impl FnMut() -> Result<(), E>,
    ) -> Result<Vec<EncodingMatch>, E> {
        let all = self.encoding_candidates(data, checkpoint)?;
        if all.len() <= 1 {
            return Ok(all);
        }

        let mut filtered = Vec::with_capacity(all.len());
        for (index, candidate) in all.iter().copied().enumerate() {
            checkpoint()?;
            let shadowed_by_previous = index.checked_sub(1).is_some_and(|previous| {
                let neighbor = all[previous];
                candidate.range.overlaps(neighbor.range)
                    && neighbor.encoding.precedence() > candidate.encoding.precedence()
            });
            let shadowed_by_next = all.get(index + 1).is_some_and(|neighbor| {
                candidate.range.overlaps(neighbor.range)
                    && neighbor.encoding.precedence() > candidate.encoding.precedence()
            });
            if !shadowed_by_previous && !shadowed_by_next {
                filtered.push(candidate);
            }
        }
        Ok(filtered)
    }
}

/// Returns the segments whose decoded span overlaps `start..=end`.
///
/// `segments` comes from one decode pass, or a contiguous run of one, so the
/// inclusive [`StartEnd::overlaps`] matches form a contiguous range; see
/// [`segments_are_ordered_and_disjoint`].
/// Names the [`ENCODINGS_PATTERN`] alternative that produced one whole match.
///
/// `span` must be the bytes of a match of that pattern. Each alternative is its
/// own whole capture group, so the capture index equals the first alternative
/// able to match at the span start:
///
/// * `%` starts only the percent alternative. No other alternative can begin
///   with it.
/// * `\` starts only the second unicode branch. `(?i)` is scoped to that
///   branch and only affects `u`/`U` and the hex digits inside it.
/// * `U` starts the first unicode branch or base64. That branch is tried
///   first and needs one complete `U+hhhh` group, which ends in Go `\s`
///   (`[\t\n\f\r ]`) or at end of text. So a unicode match has that whitespace
///   at offset 6 or has length 6, while base64 has at least 16 bytes from its
///   class, which excludes whitespace, at offset 6.
/// * Any other first byte is hex or base64. Hex is tried first and is greedy,
///   so it matches exactly when the maximal hex-digit run from the span start
///   has at least 32 bytes, in which case the whole span is that run.
///
/// `.` and `$` only decide where a match ends, which is already given by
/// `span`. An invalid UTF-8 byte can only lie inside a percent span, because
/// the other alternatives are ASCII-only, and a percent span starts at an
/// ASCII `%` that normalization maps back to the same source byte.
fn classify_encoding_span(span: &[u8]) -> Encoding {
    match span.first() {
        Some(b'%') => Encoding::Percent,
        Some(b'\\') => Encoding::Unicode,
        Some(b'U')
            if span.len() == 6
                || matches!(span.get(6), Some(b'\t' | b'\n' | 0x0c | b'\r' | b' ')) =>
        {
            Encoding::Unicode
        }
        _ if span.len() >= 32 && span.iter().all(u8::is_ascii_hexdigit) => Encoding::Hex,
        _ => Encoding::Base64,
    }
}

pub(crate) fn segments_with_decoded_overlap(
    segments: &[EncodedSegment],
    start: usize,
    end: usize,
) -> &[EncodedSegment] {
    let range = StartEnd {
        start: isize::try_from(start).unwrap(),
        end: isize::try_from(end).unwrap(),
    };
    &segments[overlapping_indices(segments, range)]
}

/// Whether decoded spans are non-empty, strictly ascending, and disjoint.
/// Adjacent spans (equal end and start) count as disjoint.
///
/// This holds by construction for the segments of one decode pass:
///
/// * accepted decoded values are non-empty, so every span is non-empty;
/// * the regex yields ordered, non-overlapping matches, and shadow filtering
///   only removes matches, so accepted candidates ascend with `end <= next
///   start`;
/// * after accepting a segment, `decoded_shift` is the difference between the
///   decoded and encoded length of all accepted segments, so that segment's
///   decoded end is its candidate end plus the shift and the next accepted
///   segment's decoded start is its candidate start plus that same shift.
///
/// Consequently `start` and `end` both strictly ascend across the segments.
/// Asserted in debug builds where segments are built, not per lookup.
fn segments_are_ordered_and_disjoint(segments: &[EncodedSegment]) -> bool {
    segments
        .iter()
        .all(|segment| segment.decoded.start < segment.decoded.end)
        && segments
            .windows(2)
            .all(|pair| pair[0].decoded.end <= pair[1].decoded.start)
}

/// Returns the index range of `segments` whose decoded span overlaps `range`
/// under the inclusive [`StartEnd::overlaps`] test, adjacency included.
///
/// Both endpoints ascend across ordered disjoint spans, so `end >= range.start`
/// holds on a suffix and `start <= range.end` holds on a prefix, and the
/// overlaps are exactly their intersection.
fn overlapping_indices(segments: &[EncodedSegment], range: StartEnd) -> Range<usize> {
    let first = segments.partition_point(|segment| segment.decoded.end < range.start);
    let past_last = segments.partition_point(|segment| segment.decoded.start <= range.end);
    first..past_last.max(first)
}

/// Records, for each segment, the same bounds [`current_line`] would find by
/// scanning outward from that segment alone.
///
/// `segments` must be ordered and disjoint against `output`, so the two
/// scanned positions only move forward and the sweep inspects no output byte
/// more than twice.
fn record_line_bounds(segments: &mut [EncodedSegment], output: &[u8]) {
    let mut previous_newline = 0;
    let mut scanned_up_to = 0;
    let mut next_newline = 0;
    for segment in segments {
        let decoded_start = usize::try_from(segment.decoded.start).unwrap();
        let decoded_end = usize::try_from(segment.decoded.end).unwrap();

        if let Some(found) = output[scanned_up_to..=decoded_start]
            .iter()
            .rposition(|byte| *byte == b'\n')
        {
            previous_newline = scanned_up_to + found;
        }
        scanned_up_to = decoded_start + 1;

        // A previous answer remains the first newline at or after a larger
        // end while it is not behind that end. It starts at zero, which is
        // behind every non-empty span's end, so the first segment scans.
        if next_newline < decoded_end {
            next_newline = output[decoded_end..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(output.len(), |offset| decoded_end + offset);
        }

        segment.line = LineBounds {
            start: previous_newline,
            end: next_newline,
        };
    }
}

pub(crate) fn adjust_match_index(
    segments: &[EncodedSegment],
    start: usize,
    end: usize,
) -> Option<(usize, usize)> {
    if segments.is_empty() {
        return Some((start, end));
    }
    let adjusted = to_original(
        segments,
        StartEnd {
            start: isize::try_from(start).ok()?,
            end: isize::try_from(end).ok()?,
        },
    );
    Some((
        usize::try_from(adjusted.start).ok()?,
        usize::try_from(adjusted.end).ok()?,
    ))
}

/// Returns the line around the merged decoded span of `segments`: from the
/// last newline at or before its start through the byte before the first
/// newline at or after its end. `current_raw` must be the decode pass output
/// that produced `segments`.
pub(crate) fn current_line<'a>(segments: &[EncodedSegment], current_raw: &'a [u8]) -> &'a [u8] {
    if segments.is_empty() {
        return current_raw;
    }
    // The merged span starts at the smallest decoded start and ends at the
    // largest decoded end. A segment's recorded bounds depend only on those
    // positions, so the two extreme segments supply the merged bounds.
    let (mut earliest, mut latest) = (&segments[0], &segments[0]);
    for segment in &segments[1..] {
        if segment.decoded.start < earliest.decoded.start {
            earliest = segment;
        }
        if segment.decoded.end > latest.decoded.end {
            latest = segment;
        }
    }
    &current_raw[earliest.line.start..latest.line.end]
}

pub(crate) fn tags(segments: &[EncodedSegment]) -> Vec<String> {
    let Some(first) = segments.first() else {
        return Vec::new();
    };
    let encodings = segments
        .iter()
        .fold(0, |combined, segment| combined | segment.encodings);
    let mut tags = Encoding::ALL
        .into_iter()
        .filter(|encoding| encodings & encoding.bit() != 0)
        .map(|encoding| format!("decoded:{}", encoding.name()))
        .collect::<Vec<_>>();
    tags.push(format!("decode-depth:{}", first.depth));
    tags
}

fn to_original(predecessors: &[EncodedSegment], decoded: StartEnd) -> StartEnd {
    if predecessors.is_empty() {
        return decoded;
    }
    let mut encoded = StartEnd::default();
    for predecessor in predecessors {
        if !predecessor.decoded.overlaps(decoded) {
            continue;
        }
        if predecessor.decoded.contains(decoded) {
            return predecessor.original;
        }
        let mapped = predecessor
            .encoded
            .add(predecessor.decoded.overflow(decoded));
        encoded = if encoded.end == 0 {
            mapped
        } else {
            encoded.merge(mapped)
        };
    }
    if encoded.end == 0 {
        return decoded;
    }
    to_original(&predecessors[0].predecessors, encoded)
}

fn append_percent(encoded: &[u8], output: &mut Vec<u8>) {
    let value_start = output.len();
    output.reserve(encoded.len());
    let mut index = 0;
    while index < encoded.len() {
        if encoded[index] == b'%'
            && index + 2 < encoded.len()
            && let (Some(high), Some(low)) = (
                hex_nibble(encoded[index + 1]),
                hex_nibble(encoded[index + 2]),
            )
        {
            let byte = (high << 4) | low;
            if !is_printable_ascii(byte) {
                output.truncate(value_start);
                return;
            }
            output.push(byte);
            index += 3;
            continue;
        }
        output.push(encoded[index]);
        index += 1;
    }
}

fn append_hex(encoded: &[u8], output: &mut Vec<u8>) {
    if !encoded.len().is_multiple_of(2) || !encoded.iter().any(u8::is_ascii_digit) {
        return;
    }
    let value_start = output.len();
    output.reserve(encoded.len() / 2);
    for pair in encoded.chunks_exact(2) {
        let (Some(high), Some(low)) = (hex_nibble(pair[0]), hex_nibble(pair[1])) else {
            output.truncate(value_start);
            return;
        };
        let byte = (high << 4) | low;
        if !is_printable_ascii(byte) {
            output.truncate(value_start);
            return;
        }
        output.push(byte);
    }
}

fn append_base64(encoded: &[u8], output: &mut Vec<u8>) {
    if !encoded
        .iter()
        .any(|byte| matches!(byte, b'0'..=b'9' | b'+' | b'/' | b'-' | b'_'))
    {
        return;
    }
    let value_start = output.len();
    for engine in [&GO_STANDARD_BASE64, &GO_RAW_URL_BASE64] {
        if engine.decode_vec(encoded, output).is_ok()
            && output[value_start..]
                .iter()
                .copied()
                .all(is_printable_ascii)
        {
            return;
        }
        // `decode_vec` leaves a conservatively sized, partly written tail on
        // failure, so every rejected attempt restores the prior length.
        output.truncate(value_start);
    }
}

fn append_unicode(encoded: &[u8], output: &mut Vec<u8>) {
    if encoded.starts_with(b"U+") {
        for digits in encoded
            .split(u8::is_ascii_whitespace)
            .filter(|field| !field.is_empty())
            .filter_map(|field| field.strip_prefix(b"U+"))
            .filter(|digits| digits.len() >= 4)
        {
            push_unicode_escape(output, &digits[..4]);
        }
        return;
    }

    let mut index = 0;
    while index < encoded.len() {
        let slash_count = if encoded[index..].starts_with(b"\\\\") {
            2
        } else if encoded[index..].starts_with(b"\\") {
            1
        } else {
            break;
        };
        let u_index = index + slash_count;
        if !encoded
            .get(u_index)
            .is_some_and(|byte| matches!(byte, b'u' | b'U'))
        {
            break;
        }
        let digits_start = u_index + 1;
        let Some(digits) = encoded.get(digits_start..digits_start + 4) else {
            break;
        };
        push_unicode_escape(output, digits);
        index = digits_start + 4;
    }
}

fn push_unicode_escape(output: &mut Vec<u8>, digits: &[u8]) {
    let Some(value) = parse_hex_u32(digits) else {
        return;
    };
    let scalar = char::from_u32(value).unwrap_or(char::REPLACEMENT_CHARACTER);
    let mut buffer = [0; 4];
    output.extend_from_slice(scalar.encode_utf8(&mut buffer).as_bytes());
}

fn parse_hex_u32(digits: &[u8]) -> Option<u32> {
    digits.iter().try_fold(0u32, |value, byte| {
        value
            .checked_mul(16)?
            .checked_add(u32::from(hex_nibble(*byte)?))
    })
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

const fn is_printable_ascii(byte: u8) -> bool {
    byte > 0x08 && byte < 0x7f
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct OracleOutcome {
        id: String,
        operation: String,
        runs: Vec<OracleRun>,
    }

    #[derive(Deserialize)]
    struct OracleRequest {
        id: String,
        operation: String,
        #[serde(default = "default_decoder_scope")]
        decoder_scope: String,
        #[serde(default)]
        carry_predecessors_across_inputs: bool,
    }

    fn default_decoder_scope() -> String {
        "shared".to_owned()
    }

    #[derive(Deserialize)]
    struct OracleRun {
        input_base64: String,
        full_decode_base64: String,
        terminated: bool,
        cache_before: Vec<OracleCacheEntry>,
        cache_after: Vec<OracleCacheEntry>,
        passes: Vec<OraclePass>,
    }

    #[derive(Deserialize)]
    struct OracleCacheEntry {
        encoded_base64: String,
        decoded_base64: String,
    }

    #[derive(Deserialize)]
    struct OraclePass {
        pass: usize,
        input_base64: String,
        output_base64: String,
        cache_before: Vec<OracleCacheEntry>,
        cache_after: Vec<OracleCacheEntry>,
        segments: Vec<OracleSegment>,
        tags_base64: Vec<String>,
        current_line_base64: String,
        probes: Vec<OracleProbe>,
    }

    #[derive(Deserialize)]
    struct OracleSegment {
        index: usize,
        original: [isize; 2],
        encoded: [isize; 2],
        decoded: [isize; 2],
        decoded_value_base64: String,
        encoding_mask: u8,
        encoding_kinds: Vec<String>,
        depth: usize,
        predecessor_indices: Vec<usize>,
    }

    #[derive(Deserialize)]
    struct OracleProbe {
        range: [usize; 2],
        adjusted: [usize; 2],
        overlap_segment_indices: Vec<usize>,
    }

    fn decoded_with(append: fn(&[u8], &mut Vec<u8>), encoded: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        append(encoded, &mut output);
        output
    }

    fn decode_percent(encoded: &[u8]) -> Vec<u8> {
        decoded_with(append_percent, encoded)
    }

    fn decode_hex(encoded: &[u8]) -> Vec<u8> {
        decoded_with(append_hex, encoded)
    }

    fn decode_base64(encoded: &[u8]) -> Vec<u8> {
        decoded_with(append_base64, encoded)
    }

    fn decode_unicode(encoded: &[u8]) -> Vec<u8> {
        decoded_with(append_unicode, encoded)
    }

    fn oracle_bytes(encoded: &str) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap()
    }

    fn oracle_cache(entries: &[OracleCacheEntry]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut decoded = entries
            .iter()
            .map(|entry| {
                (
                    oracle_bytes(&entry.encoded_base64),
                    oracle_bytes(&entry.decoded_base64),
                )
            })
            .collect::<Vec<_>>();
        decoded.sort_by(|left, right| left.0.cmp(&right.0));
        decoded
    }

    fn rust_cache(decoder: &Decoder) -> Vec<(Vec<u8>, Vec<u8>)> {
        decoder
            .decoded
            .iter()
            .map(|(encoded, decoded)| (encoded.clone(), decoded.to_vec()))
            .collect()
    }

    fn fully_decode(decoder: &mut Decoder, mut data: Vec<u8>) -> Vec<u8> {
        let mut segments = Vec::new();
        loop {
            let (next, next_segments) = decoder.decode(&data, &segments);
            data = next;
            segments = next_segments;
            if segments.is_empty() {
                return data;
            }
        }
    }

    fn percent_encode(data: &[u8]) -> Vec<u8> {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        let mut encoded = Vec::with_capacity(data.len() * 3);
        for &byte in data {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
                encoded.push(byte);
            } else {
                encoded.extend_from_slice(&[
                    b'%',
                    HEX[usize::from(byte >> 4)],
                    HEX[usize::from(byte & 0x0f)],
                ]);
            }
        }
        encoded
    }

    fn hex_encode(data: &[u8]) -> Vec<u8> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        data.iter()
            .flat_map(|byte| [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 0x0f)]])
            .collect()
    }

    #[test]
    fn primitive_decoders_preserve_the_pinned_filters() {
        assert_eq!(decode_percent(b"token%3dvalue"), b"token=value");
        assert!(decode_percent(b"%00").is_empty());
        assert_eq!(
            decode_hex(b"746f6b656e3d6162636465666768696a"),
            b"token=abcdefghij"
        );
        assert!(decode_hex(b"abcdefabcdefabcdefabcdefabcdefab").is_empty());
        assert_eq!(
            decode_base64(b"dG9rZW49YWJjZGVmZ2hpag=="),
            b"token=abcdefghij"
        );
        for noncanonical in [
            b"QUFBQUFBQUFBQUF+LQ==".as_slice(),
            b"QUFBQUFBQUFBQUF+LR==",
            b"QUFBQUFBQUFBQUF+LS==",
            b"QUFBQUFBQUFBQUF+LT==",
        ] {
            assert_eq!(decode_base64(noncanonical), b"AAAAAAAAAAA~-");
        }
        assert_eq!(decode_unicode(br"\u0074\u006f\u006b\u0065\u006e"), b"token");
        assert_eq!(
            decode_unicode(b"U+0074 U+006f U+006b U+0065 U+006e "),
            b"token"
        );
    }

    #[test]
    fn maps_nested_segments_to_the_original_candidate() {
        let mut decoder = Decoder::new();
        let (first, first_segments) =
            decoder.decode(b"prefix ZEc5clpXNDlZV0pqWkdWbVoyaHBhZz09 suffix", &[]);
        assert!(!first_segments.is_empty());
        let (_second, second_segments) = decoder.decode(&first, &first_segments);
        assert!(!second_segments.is_empty());
        assert_eq!(second_segments[0].depth(), 2);
        assert_eq!(second_segments[0].original(), first_segments[0].original());
        assert_eq!(
            tags(&second_segments),
            vec!["decoded:base64", "decode-depth:2"]
        );
    }

    #[test]
    fn maps_every_overlap_geometry_with_signed_overflow() {
        let segment = |encoded: StartEnd, decoded: StartEnd| EncodedSegment {
            predecessors: Arc::from([]),
            original: encoded,
            encoded,
            decoded,
            decoded_value: Arc::from([]),
            encodings: Encoding::Base64.bit(),
            depth: 1,
            line: LineBounds::default(),
        };
        let first = segment(
            StartEnd { start: 10, end: 20 },
            StartEnd { start: 10, end: 15 },
        );

        assert_eq!(
            to_original(
                std::slice::from_ref(&first),
                StartEnd { start: 11, end: 14 }
            ),
            StartEnd { start: 10, end: 20 }
        );
        assert_eq!(
            to_original(std::slice::from_ref(&first), StartEnd { start: 8, end: 12 }),
            StartEnd { start: 8, end: 20 }
        );
        assert_eq!(
            to_original(
                std::slice::from_ref(&first),
                StartEnd { start: 13, end: 17 }
            ),
            StartEnd { start: 10, end: 22 }
        );
        assert_eq!(
            to_original(std::slice::from_ref(&first), StartEnd { start: 8, end: 17 }),
            StartEnd { start: 8, end: 22 }
        );
        assert_eq!(
            to_original(std::slice::from_ref(&first), StartEnd { start: 0, end: 5 }),
            StartEnd { start: 0, end: 5 }
        );
        assert_eq!(
            to_original(std::slice::from_ref(&first), StartEnd { start: 5, end: 10 }),
            StartEnd { start: 5, end: 20 }
        );
        assert_eq!(
            to_original(
                std::slice::from_ref(&first),
                StartEnd { start: 15, end: 18 }
            ),
            StartEnd { start: 10, end: 23 }
        );

        let second = segment(
            StartEnd { start: 22, end: 32 },
            StartEnd { start: 17, end: 22 },
        );
        assert_eq!(
            to_original(&[first, second], StartEnd { start: 12, end: 20 }),
            StartEnd { start: 10, end: 32 }
        );
    }

    #[test]
    fn cache_is_per_decoder_and_reused_when_a_candidate_reappears() {
        let candidate = b"dGhpcy1pcy0xMjM0";
        let outer = GO_STANDARD_BASE64.encode(candidate);

        let mut decoder = Decoder::new();
        let (_decoded, cached_candidate_segments) = decoder.decode(candidate, &[]);
        assert_eq!(cached_candidate_segments.len(), 1);
        let (first, first_segments) = decoder.decode(outer.as_bytes(), &[]);
        assert_eq!(first_segments.len(), 1);
        assert_eq!(decoder.decoded.len(), 2);

        let (_second, second_segments) = decoder.decode(&first, &first_segments);
        assert_eq!(second_segments.len(), 1);
        assert_eq!(decoder.decoded.len(), 2);
        assert_eq!(second_segments[0].depth(), 2);
        assert!(Arc::ptr_eq(
            &cached_candidate_segments[0].decoded_value,
            &second_segments[0].decoded_value
        ));

        let rejected = b"AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAA";
        let (_unchanged, rejected_segments) = decoder.decode(rejected, &[]);
        assert!(rejected_segments.is_empty());
        assert_eq!(decoder.decoded.len(), 3);

        let mut isolated = Decoder::new();
        assert!(isolated.decoded.is_empty());
        let (_unchanged, isolated_segments) = isolated.decode(rejected, &[]);
        assert!(isolated_segments.is_empty());
        assert_eq!(isolated.decoded.len(), 1);
        assert_eq!(decoder.decoded.len(), 3);
    }

    /// Replays the pass chain of every decode corpus run with an isolated
    /// decoder, giving each pass its input, predecessors, output, and segments.
    fn for_each_corpus_pass(
        mut visit: impl FnMut(&str, &[u8], &[EncodedSegment], &[u8], &[EncodedSegment]),
    ) {
        let corpus = include_str!("../../../../compat/decoder-corpus/outcomes-v1.jsonl");
        for outcome in corpus
            .lines()
            .map(|line| serde_json::from_str::<OracleOutcome>(line).unwrap())
            .filter(|outcome| outcome.operation == "decode")
        {
            for run in outcome.runs {
                let mut decoder = Decoder::new();
                let mut current = oracle_bytes(&run.input_base64);
                let mut predecessors = Vec::new();
                for _ in &run.passes {
                    let (output, segments) = decoder.decode(&current, &predecessors);
                    visit(&outcome.id, &current, &predecessors, &output, &segments);
                    current = output;
                    predecessors = segments;
                }
            }
        }
    }

    /// Synthetic passes for line and overlap checks that the corpus does not
    /// reach: adjacent segments, newlines at segment edges and inside decoded
    /// values, and files with no newline at all.
    const LINE_BOUND_CASES: &[&[u8]] = &[
        b"QUJDREVGR0hJSktMTU5PUA==QUJDREVGR0hJSktMTU5PUA==",
        b"one\ntwo QUJDREVGR0hJSktMTU5PUA== three\nfour %0Aabc%0A tail\n",
        b"x%0Aabc%0Ay",
        b"QUJDREVGR0hJSktMTU5PUA==\nrest",
        b"head\nQUJDREVGR0hJSktMTU5PUA==",
        b"\n\nQUJDREVGR0hJSktMTU5PUA==\n\nQUJDREVGR0hJSktMTU5PUA==\n\n",
        b"QUJDREVGR0hJSktMTU5PUA== dGhpcy1pcy0xMjM0",
        b"a%0Ab\nQUJDREVGR0hJSktMTU5PUA==%0A\nc",
    ];

    fn decoded_probe_positions(segments: &[EncodedSegment]) -> Vec<isize> {
        let mut positions = vec![-1, 0];
        for segment in segments.iter().take(32) {
            for boundary in [segment.decoded.start, segment.decoded.end] {
                positions.extend([boundary - 1, boundary, boundary + 1]);
            }
        }
        if let Some(last) = segments.last() {
            positions.extend([last.decoded.end, last.decoded.end + 1, last.decoded.end + 2]);
        }
        positions.retain(|position| *position >= 0);
        positions.sort_unstable();
        positions.dedup();
        positions
    }

    /// The pre-memo scan used directly as the behaviour specification.
    fn line_by_scanning<'a>(segments: &[EncodedSegment], raw: &'a [u8]) -> &'a [u8] {
        let decoded = segments
            .iter()
            .skip(1)
            .fold(segments[0].decoded, |range, segment| {
                range.merge(segment.decoded)
            });
        let decoded_start = usize::try_from(decoded.start).unwrap();
        let decoded_end = usize::try_from(decoded.end).unwrap();
        let start = (0..=decoded_start)
            .rev()
            .find(|&index| raw[index] == b'\n')
            .unwrap_or(0);
        let end = (decoded_end..raw.len())
            .find(|&index| raw[index] == b'\n')
            .unwrap_or(raw.len());
        &raw[start..end]
    }

    fn assert_overlap_lookup_matches_linear_filter(id: &str, segments: &[EncodedSegment]) {
        let positions = decoded_probe_positions(segments);
        for (index, &start) in positions.iter().enumerate() {
            for &end in &positions[index..] {
                let range = StartEnd { start, end };
                let linear = segments
                    .iter()
                    .enumerate()
                    .filter(|(_, segment)| segment.decoded.overlaps(range))
                    .map(|(position, _)| position)
                    .collect::<Vec<_>>();
                let found = overlapping_indices(segments, range).collect::<Vec<_>>();
                assert_eq!(found, linear, "{id} probe {start}..{end}");
                let via_public = segments_with_decoded_overlap(
                    segments,
                    usize::try_from(start).unwrap(),
                    usize::try_from(end).unwrap(),
                );
                assert_eq!(via_public.len(), linear.len(), "{id} probe {start}..{end}");
            }
        }
    }

    fn assert_line_matches_scan(id: &str, segments: &[EncodedSegment], output: &[u8]) {
        for first in 0..segments.len().min(24) {
            for last in first..segments.len().min(24) {
                let run = &segments[first..=last];
                assert_eq!(
                    current_line(run, output),
                    line_by_scanning(run, output),
                    "{id} segments {first}..={last}"
                );
            }
        }
    }

    /// The pre-classifier candidate discovery, kept as the differential oracle.
    fn candidates_from_captures(decoder: &Decoder, data: &[u8]) -> Vec<EncodingMatch> {
        let mut all = Vec::new();
        for captures in decoder.encodings.captures_all(data) {
            let groups = captures.spans()[1..].iter().flatten().count();
            assert_eq!(groups, 1, "{data:?} produced {groups} groups");
            for (index, span) in captures.spans().iter().enumerate().skip(1) {
                if let Some(span) = span {
                    all.push(EncodingMatch {
                        encoding: Encoding::ALL[index - 1],
                        range: StartEnd {
                            start: isize::try_from(span.start).unwrap(),
                            end: isize::try_from(span.end).unwrap(),
                        },
                    });
                }
            }
        }
        all
    }

    fn assert_classifier_matches_captures(decoder: &Decoder, data: &[u8], context: &str) {
        let classified = decoder
            .encoding_candidates(data, &mut || Ok::<(), Infallible>(()))
            .unwrap_or_else(|never| match never {});
        assert_eq!(
            classified,
            candidates_from_captures(decoder, data),
            "{context}: {data:?}"
        );
    }

    #[test]
    fn classified_candidates_match_the_expected_alternatives() {
        use Encoding::{Base64, Hex, Percent, Unicode};

        type ExpectedSpan = (Encoding, isize, isize);

        const HEX_32: &[u8; 32] = b"0123456789abcdef0123456789ABCDEF";
        let hex_32_equals = [HEX_32.as_slice(), b"="].concat();
        let hex_32_z = [HEX_32.as_slice(), b"Z"].concat();
        let cases: &[(&[u8], &[ExpectedSpan])] = &[
            // Percent: `.` stops at a newline but consumes invalid bytes as
            // single runes, with offsets mapped back to the source bytes.
            (b"%41%42", &[(Percent, 0, 6)]),
            (b"%41\n%42", &[(Percent, 0, 3), (Percent, 4, 7)]),
            (b"%41\xff%42", &[(Percent, 0, 7)]),
            (b"%41\xff", &[(Percent, 0, 3)]),
            ("é%41".as_bytes(), &[(Percent, 2, 5)]),
            (b"%4", &[]),
            // First unicode branch: end of text, Go whitespace only.
            (b"U+0041", &[(Unicode, 0, 6)]),
            (b"U+0041 ", &[(Unicode, 0, 7)]),
            (b"U+0041\n", &[(Unicode, 0, 7)]),
            (b"U+0041\t", &[(Unicode, 0, 7)]),
            (b"U+0041 U+0042", &[(Unicode, 0, 13)]),
            (b"U+0041 U+0042X", &[(Unicode, 0, 7)]),
            (b"U+0041\x0b", &[]),
            (b"U+0041\xff", &[]),
            (b"u+0041", &[]),
            // A longer run is base64 once the `U+hhhh` group cannot end.
            (b"U+00412345678901234", &[(Base64, 0, 19)]),
            // Second unicode branch: `(?i)` covers only `u` and the digits.
            (b"\\u0041", &[(Unicode, 0, 6)]),
            (b"\\U0041", &[(Unicode, 0, 6)]),
            (b"\\\\u0041", &[(Unicode, 0, 7)]),
            (b"\\\\\\u0041", &[(Unicode, 1, 8)]),
            (b"\\uABCD\\uabcd", &[(Unicode, 0, 12)]),
            (b"\\u004", &[]),
            // Hex precedes base64 at 32 bytes and base64 takes shorter runs.
            (HEX_32, &[(Hex, 0, 32)]),
            (b"0123456789abcdef0123456789ABCDE", &[(Base64, 0, 31)]),
            (b"0123456789abcdef==", &[(Base64, 0, 18)]),
            (b"deadbeefdeadbeefg", &[(Base64, 0, 17)]),
            (hex_32_equals.as_slice(), &[(Hex, 0, 32)]),
            (hex_32_z.as_slice(), &[(Hex, 0, 32)]),
            // Base64 alphabet, padding, and invalid bytes around it.
            (b"abcdefghijklmnop", &[(Base64, 0, 16)]),
            (b"AB/+-_abcdefghijk", &[(Base64, 0, 17)]),
            (b"QUJDREVGR0hJSktM===", &[(Base64, 0, 18)]),
            (b"\xffABCDEFGHIJKLMNOP", &[(Base64, 1, 17)]),
            (b"ABCDEFGHIJKLMNOP\xff", &[(Base64, 0, 16)]),
            (b"\xef\xbf\xbdABCDEFGHIJKLMNOP", &[(Base64, 3, 19)]),
            // Each alternative in one haystack.
            (
                b"%41 QUJDREVGR0hJSktMTU5PUA== \\u0041 0123456789abcdef0123456789abcdef U+0041",
                &[
                    (Percent, 0, 3),
                    (Base64, 4, 28),
                    (Unicode, 29, 35),
                    (Hex, 36, 68),
                    (Unicode, 69, 75),
                ],
            ),
        ];

        let decoder = Decoder::new();
        for &(data, expected) in cases {
            let expected = expected
                .iter()
                .map(|&(encoding, start, end)| EncodingMatch {
                    encoding,
                    range: StartEnd { start, end },
                })
                .collect::<Vec<_>>();
            let classified = decoder
                .encoding_candidates(data, &mut || Ok::<(), Infallible>(()))
                .unwrap_or_else(|never| match never {});
            assert_eq!(classified, expected, "{data:?}");
            assert_eq!(
                candidates_from_captures(&decoder, data),
                expected,
                "{data:?}"
            );
        }
    }

    #[test]
    fn classifier_matches_capture_groups_on_the_corpus_and_token_grid() {
        let decoder = Decoder::new();
        for_each_corpus_pass(|id, input, _predecessors, _output, _segments| {
            assert_classifier_matches_captures(&decoder, input, id);
        });

        const TOKENS: &[&[u8]] = &[
            b"%41",
            b"%4",
            b"%",
            b"%zz",
            b"U+0041",
            b"U+00",
            b"u+0041",
            b"U+",
            b"\\u0041",
            b"\\U00ff",
            b"\\\\u0041",
            b"\\u00",
            b"0123456789abcdef",
            b"ABCDEF0123456789",
            b"0123456789abcdef0123456789abcdef",
            b"gGzZ_/+-wxyzQRST",
            b"=",
            b"==",
            b" ",
            b"\n",
            b"\t",
            b"\r",
            b"\x0b",
            b"\x0c",
            b"\xff",
            b"\xc3",
            b"\xe2\x82",
            b"\xc3\xa9",
            b"\xef\xbf\xbd",
            b".",
            b"-",
        ];
        let mut haystack = Vec::new();
        for first in TOKENS {
            for second in TOKENS {
                for third in TOKENS {
                    haystack.clear();
                    haystack.extend_from_slice(first);
                    haystack.extend_from_slice(second);
                    haystack.extend_from_slice(third);
                    assert_classifier_matches_captures(&decoder, &haystack, "grid");
                }
            }
        }

        // A deterministic generator over the same tokens exercises longer
        // repetitions, including unicode runs that span many groups.
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = |bound: usize| {
            state = state.wrapping_mul(0x5851_f42d_4c95_7f2d).wrapping_add(1);
            usize::try_from((state >> 33) % u64::try_from(bound).unwrap()).unwrap()
        };
        for _ in 0..4_000 {
            haystack.clear();
            for _ in 0..4 + next(9) {
                haystack.extend_from_slice(TOKENS[next(TOKENS.len())]);
            }
            assert_classifier_matches_captures(&decoder, &haystack, "generated");
        }
    }

    fn controlled_output(decoder: &mut Decoder, data: &[u8]) -> (Vec<u8>, Vec<EncodedSegment>) {
        decoder
            .decode_controlled(data, &[], || Ok::<(), Infallible>(()))
            .unwrap_or_else(|never| match never {})
    }

    /// The pre-merge assembly, kept as the expected output for a segment list.
    fn output_from_segments(data: &[u8], segments: &[EncodedSegment]) -> Vec<u8> {
        let mut result = Vec::with_capacity(data.len());
        let mut encoded_start = 0;
        for segment in segments {
            let encoded = segment.encoded.as_usize().unwrap();
            result.extend_from_slice(&data[encoded_start..encoded.start]);
            result.extend_from_slice(&segment.decoded_value);
            encoded_start = encoded.end;
        }
        result.extend_from_slice(&data[encoded_start..]);
        result
    }

    #[test]
    fn a_pass_that_decodes_nothing_returns_an_unallocated_buffer() {
        for data in [
            b"no candidates here".as_slice(),
            b"AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAA",
            b"",
        ] {
            let mut decoder = Decoder::new();
            let (output, segments) = controlled_output(&mut decoder, data);
            assert!(segments.is_empty(), "{data:?}");
            assert_eq!(output.capacity(), 0, "{data:?}");

            let (full, segments) = Decoder::new().decode(data, &[]);
            assert!(segments.is_empty(), "{data:?}");
            assert_eq!(full, data, "{data:?}");
        }
    }

    #[test]
    fn output_assembly_keeps_rejected_candidates_and_reuses_cached_values() {
        // In order: a rejected candidate before the first accepted segment, a
        // decode miss in the first and second accepted positions, a rejected
        // candidate between accepted segments, and a cache hit last.
        let data = b"AAAAAAAAAAAAAAAA AB QUJDREVGR0hJSktMTU5PUA== CD dGhpcy1pcy0xMjM0 EF AAAAAAAAAAAAAAAA GH dGhpcy1pcy0xMjM0";
        let mut decoder = Decoder::new();
        let (output, segments) = decoder.decode(data, &[]);

        assert_eq!(
            output,
            b"AAAAAAAAAAAAAAAA AB ABCDEFGHIJKLMNOP CD this-is-1234 EF AAAAAAAAAAAAAAAA GH this-is-1234"
        );
        assert_eq!(output, output_from_segments(data, &segments));
        assert_eq!(segments.len(), 3);

        // Hand-computed offsets: the first value decodes 24 bytes into 16.
        assert_eq!(segments[0].encoded, StartEnd { start: 20, end: 44 });
        assert_eq!(segments[0].decoded, StartEnd { start: 20, end: 36 });
        assert_eq!(segments[1].encoded, StartEnd { start: 48, end: 64 });
        assert_eq!(segments[1].decoded, StartEnd { start: 40, end: 52 });
        assert_eq!(
            segments[2].encoded,
            StartEnd {
                start: 88,
                end: 104
            }
        );
        assert_eq!(segments[2].decoded, StartEnd { start: 76, end: 88 });
        assert_eq!(segments[1].decoded_value(), b"this-is-1234");
        assert!(Arc::ptr_eq(
            &segments[1].decoded_value,
            &segments[2].decoded_value
        ));

        assert_eq!(
            rust_cache(&decoder),
            vec![
                (b"AAAAAAAAAAAAAAAA".to_vec(), Vec::new()),
                (
                    b"QUJDREVGR0hJSktMTU5PUA==".to_vec(),
                    b"ABCDEFGHIJKLMNOP".to_vec()
                ),
                (b"dGhpcy1pcy0xMjM0".to_vec(), b"this-is-1234".to_vec()),
            ]
        );

        // The first accepted value still decodes when no candidate preceded it.
        let (output, segments) = Decoder::new().decode(b"QUJDREVGR0hJSktMTU5PUA== tail", &[]);
        assert_eq!(output, b"ABCDEFGHIJKLMNOP tail");
        assert_eq!(segments[0].decoded, StartEnd { start: 0, end: 16 });
    }

    #[test]
    fn assembled_output_matches_the_segments_across_the_corpus() {
        for_each_corpus_pass(|id, input, _predecessors, output, segments| {
            assert_eq!(output, output_from_segments(input, segments), "{id}");
        });
        for case in LINE_BOUND_CASES {
            let (output, segments) = Decoder::new().decode(case, &[]);
            assert_eq!(output, output_from_segments(case, &segments), "{case:?}");
        }
    }

    #[test]
    fn rejected_values_leave_the_shared_buffer_unchanged() {
        let seeded = |append: fn(&[u8], &mut Vec<u8>), encoded: &[u8]| {
            let mut output = b"seed".to_vec();
            append(encoded, &mut output);
            output
        };

        // Rejections that happen after earlier bytes were already written.
        assert_eq!(seeded(append_percent, b"%41abc%00"), b"seed");
        assert_eq!(seeded(append_hex, b"41424344454647484900"), b"seed");
        // Rejections detected before any byte is written.
        assert_eq!(
            seeded(append_hex, b"abcdefabcdefabcdefabcdefabcdefab"),
            b"seed"
        );
        assert_eq!(seeded(append_base64, b"AAAAAAAAAAAAAAAA"), b"seed");
        // Base64 failures that occur after `decode_vec` has grown the buffer.
        assert_eq!(seeded(append_base64, b"QUJD1!UJD"), b"seed");
        assert_eq!(seeded(append_base64, b"gIGCg4SFhoeIiYqLjI2Ojw=="), b"seed");
        // Accepted values append after the seed.
        assert_eq!(seeded(append_percent, b"%41"), b"seedA");
        assert_eq!(seeded(append_hex, b"41"), b"seedA");
        assert_eq!(
            seeded(append_base64, b"QUJDREVGR0hJSktMTU5PUA=="),
            b"seedABCDEFGHIJKLMNOP"
        );
        // Unicode escapes keep the prefix they could decode.
        assert_eq!(seeded(append_unicode, b"\\u0041\\x"), b"seedA");
    }

    #[test]
    fn decoded_overlap_is_inclusive_at_both_ends_and_keeps_adjacent_segments() {
        let segment = |start: isize, end: isize| {
            let span = StartEnd { start, end };
            EncodedSegment {
                predecessors: Arc::from([]),
                original: span,
                encoded: span,
                decoded: span,
                decoded_value: Arc::from([]),
                encodings: Encoding::Base64.bit(),
                depth: 1,
                line: LineBounds::default(),
            }
        };
        let segments = [segment(10, 15), segment(15, 20), segment(30, 40)];
        let indices = |start, end| {
            segments_with_decoded_overlap(&segments, start, end)
                .iter()
                .map(|selected| {
                    segments
                        .iter()
                        .position(|candidate| candidate == selected)
                        .unwrap()
                })
                .collect::<Vec<_>>()
        };

        // Touching the shared edge overlaps both adjacent segments.
        assert_eq!(indices(15, 15), [0, 1]);
        // Inclusive at the low end of the first segment.
        assert_eq!(indices(0, 10), [0]);
        assert_eq!(indices(0, 9), [] as [usize; 0]);
        // Inclusive at the high end, touching the next segment's start.
        assert_eq!(indices(20, 30), [1, 2]);
        assert_eq!(indices(21, 29), [] as [usize; 0]);
        // Inclusive past the last segment's end.
        assert_eq!(indices(40, 45), [2]);
        assert_eq!(indices(41, 45), [] as [usize; 0]);
        assert_eq!(indices(0, 100), [0, 1, 2]);
    }

    #[test]
    fn decoded_overlap_lookup_matches_a_linear_filter() {
        for case in LINE_BOUND_CASES {
            let mut decoder = Decoder::new();
            let (_output, segments) = decoder.decode(case, &[]);
            assert!(!segments.is_empty());
            assert_overlap_lookup_matches_linear_filter("synthetic", &segments);
        }
        for_each_corpus_pass(|id, _input, _predecessors, _output, segments| {
            assert_overlap_lookup_matches_linear_filter(id, segments);
        });
    }

    #[test]
    fn every_decoded_pass_yields_ordered_disjoint_segments() {
        for case in LINE_BOUND_CASES {
            let mut decoder = Decoder::new();
            let (_output, segments) = decoder.decode(case, &[]);
            assert!(segments_are_ordered_and_disjoint(&segments));
        }
        for_each_corpus_pass(|id, _input, _predecessors, _output, segments| {
            assert!(segments_are_ordered_and_disjoint(segments), "{id}");
        });
    }

    #[test]
    fn current_line_matches_the_scanned_line_for_every_segment_run() {
        for case in LINE_BOUND_CASES {
            let mut decoder = Decoder::new();
            let (output, segments) = decoder.decode(case, &[]);
            assert!(!segments.is_empty());
            assert_line_matches_scan("synthetic", &segments, &output);
        }
        for_each_corpus_pass(|id, _input, _predecessors, output, segments| {
            if !segments.is_empty() {
                assert_line_matches_scan(id, segments, output);
            }
        });
    }

    #[test]
    fn current_line_keeps_the_preceding_newline_and_stops_at_the_following_one() {
        let single = |input: &[u8]| {
            let (output, segments) = Decoder::new().decode(input, &[]);
            assert_eq!(segments.len(), 1, "{input:?}");
            (output, segments)
        };

        let (output, segments) = single(b"one\ntwo QUJDREVGR0hJSktMTU5PUA== three\nfour");
        assert_eq!(output, b"one\ntwo ABCDEFGHIJKLMNOP three\nfour");
        assert_eq!(
            current_line(&segments, &output),
            b"\ntwo ABCDEFGHIJKLMNOP three"
        );

        // No newline before the segment: the line starts at offset zero.
        let (output, segments) = single(b"QUJDREVGR0hJSktMTU5PUA==\nrest");
        assert_eq!(current_line(&segments, &output), b"ABCDEFGHIJKLMNOP");

        // No newline after the segment: the line runs to the end of output.
        let (output, segments) = single(b"head\nQUJDREVGR0hJSktMTU5PUA==");
        assert_eq!(current_line(&segments, &output), b"\nABCDEFGHIJKLMNOP");

        // A decoded value that starts with a newline starts the line there,
        // and the following newline is searched from the decoded end onward.
        let (output, segments) = single(b"x%0Aabc%0Ay");
        assert_eq!(output, b"x\nabc\ny");
        assert_eq!(segments[0].decoded, StartEnd { start: 1, end: 6 });
        assert_eq!(current_line(&segments, &output), b"\nabc\ny");
    }

    #[test]
    fn current_line_merges_the_outermost_bounds_of_a_segment_run() {
        let (output, segments) = Decoder::new().decode(
            b"aa\nQUJDREVGR0hJSktMTU5PUA==\nbb\nQUJDREVGR0hJSktMTU5PUA==\ncc",
            &[],
        );
        assert_eq!(segments.len(), 2);
        assert_eq!(current_line(&segments[..1], &output), b"\nABCDEFGHIJKLMNOP");
        assert_eq!(current_line(&segments[1..], &output), b"\nABCDEFGHIJKLMNOP");
        assert_eq!(
            current_line(&segments, &output),
            b"\nABCDEFGHIJKLMNOP\nbb\nABCDEFGHIJKLMNOP"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn matches_all_upstream_decode_table_values_and_wrappers() {
        let cases: &[(&[u8], &[u8])] = &[
            (
                b"bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q=",
                b"longer-encoded-secret-test",
            ),
            (
                b"token: bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q=",
                b"token: longer-encoded-secret-test",
            ),
            (b"", b""),
            (
                b"some-encoded-secret=dGVzdC1zZWNyZXQtdmFsdWU=",
                b"some-encoded-secret=test-secret-value",
            ),
            (
                b"some-encoded-secret=\"bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q=\"",
                b"some-encoded-secret=\"longer-encoded-secret-test\"",
            ),
            (
                b"Many substrings in this slack message could be base64 decoded\n\t\t\t\tbut only dGhpcyBlbmNhcHN1bGF0ZWQgc2VjcmV0 should be decoded.",
                b"Many substrings in this slack message could be base64 decoded\n\t\t\t\tbut only this encapsulated secret should be decoded.",
            ),
            (
                b"bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q",
                b"longer-encoded-secret-test",
            ),
            (
                b"token: bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q",
                b"token: longer-encoded-secret-test",
            ),
            (
                b"some-encoded-secret=dGVzdC1zZWNyZXQtdmFsdWU=",
                b"some-encoded-secret=test-secret-value",
            ),
            (
                b"some-encoded-secret=\"bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q\"",
                b"some-encoded-secret=\"longer-encoded-secret-test\"",
            ),
            (
                b"Z2l0bGVha3M-PmZpbmRzLXNlY3JldHM",
                b"gitleaks>>finds-secrets",
            ),
            (
                b"YjY0dXJsc2FmZS10ZXN0LXNlY3JldC11bmRlcnNjb3Jlcz8_",
                b"b64urlsafe-test-secret-underscores??",
            ),
            (
                b"a3d3fa7c2bb99e469ba55e5834ce79ee4853a8a3",
                b"a3d3fa7c2bb99e469ba55e5834ce79ee4853a8a3",
            ),
            (
                b"secret%3D%22q%24%21%40%23%24%25%5E%26%2A%28%20asdf%22",
                b"secret=\"q$!@#$%^&*( asdf\"",
            ),
            (
                b"secret=\"466973684D617048756E6B79212121363334\"",
                b"secret=\"FishMapHunky!!!634\"",
            ),
            (
                b"secret=U+0061 U+0062 U+0063 U+0064 U+0065 U+0066",
                b"secret=abcdef",
            ),
            (
                br"secret=\\u0068\\u0065\\u006c\\u006c\\u006f\\u0020\\u0077\\u006f\\u0072\\u006c\\u0064\\u0020\\u0064\\u0075\\u0064\\u0065",
                b"secret=hello world dude",
            ),
            (
                br"secret=\u0068\u0065\u006c\u006c\u006f\u0020\u0077\u006f\u0072\u006c\u0064 6C6F76656C792070656F706C65206F66206561727468",
                b"secret=hello world lovely people of earth",
            ),
        ];

        let mut decoder = Decoder::new();
        for &(input, expected) in cases {
            assert_eq!(fully_decode(&mut decoder, input.to_vec()), expected, "raw");
            assert_eq!(
                fully_decode(&mut decoder, percent_encode(input)),
                expected,
                "percent wrapped"
            );
            assert_eq!(
                fully_decode(&mut decoder, hex_encode(input)),
                expected,
                "hex wrapped"
            );
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn canonical_decoder_pass_corpus_matches_go() {
        let requests = include_str!("../../../../compat/decoder-corpus/requests-v1.jsonl")
            .lines()
            .map(|line| serde_json::from_str::<OracleRequest>(line).unwrap())
            .filter(|request| request.operation == "decode")
            .collect::<Vec<_>>();
        let corpus = include_str!("../../../../compat/decoder-corpus/outcomes-v1.jsonl");
        let outcomes = corpus
            .lines()
            .map(|line| serde_json::from_str::<OracleOutcome>(line).unwrap())
            .filter(|outcome| outcome.operation == "decode")
            .collect::<Vec<_>>();
        assert_eq!(requests.len(), 204);
        assert_eq!(outcomes.len(), 204);

        for (request, outcome) in requests.into_iter().zip(outcomes) {
            assert_eq!(request.id, outcome.id);
            assert!(matches!(
                request.decoder_scope.as_str(),
                "shared" | "isolated"
            ));
            let mut shared_decoder = Decoder::new();
            let mut carried_predecessors = Vec::new();
            for run in outcome.runs {
                let mut isolated_decoder = Decoder::new();
                let decoder = if request.decoder_scope == "isolated" {
                    &mut isolated_decoder
                } else {
                    &mut shared_decoder
                };
                assert_eq!(
                    rust_cache(decoder),
                    oracle_cache(&run.cache_before),
                    "{}",
                    outcome.id
                );
                let mut current = oracle_bytes(&run.input_base64);
                let mut predecessors = if request.carry_predecessors_across_inputs {
                    carried_predecessors.clone()
                } else {
                    Vec::new()
                };
                for (pass_index, expected) in run.passes.iter().enumerate() {
                    assert_eq!(expected.pass, pass_index + 1, "{}", outcome.id);
                    assert_eq!(
                        oracle_bytes(&expected.input_base64),
                        current,
                        "{}",
                        outcome.id
                    );
                    assert_eq!(
                        rust_cache(decoder),
                        oracle_cache(&expected.cache_before),
                        "{}",
                        outcome.id
                    );
                    let (output, segments) = decoder.decode(&current, &predecessors);
                    assert_eq!(
                        rust_cache(decoder),
                        oracle_cache(&expected.cache_after),
                        "{}",
                        outcome.id
                    );
                    assert_eq!(
                        oracle_bytes(&expected.output_base64),
                        output,
                        "{}",
                        outcome.id
                    );
                    assert_eq!(expected.segments.len(), segments.len(), "{}", outcome.id);
                    for (index, (actual, expected)) in
                        segments.iter().zip(&expected.segments).enumerate()
                    {
                        assert_eq!(expected.index, index, "{}", outcome.id);
                        assert_eq!(
                            [actual.original.start, actual.original.end],
                            expected.original,
                            "{} pass {} segment {index}",
                            outcome.id,
                            pass_index + 1
                        );
                        assert_eq!(
                            [actual.encoded.start, actual.encoded.end],
                            expected.encoded,
                            "{} pass {} segment {index}",
                            outcome.id,
                            pass_index + 1
                        );
                        assert_eq!(
                            [actual.decoded.start, actual.decoded.end],
                            expected.decoded,
                            "{} pass {} segment {index}",
                            outcome.id,
                            pass_index + 1
                        );
                        assert_eq!(
                            actual.decoded_value(),
                            oracle_bytes(&expected.decoded_value_base64),
                            "{} pass {} segment {index}",
                            outcome.id,
                            pass_index + 1
                        );
                        assert_eq!(actual.encodings, expected.encoding_mask, "{}", outcome.id);
                        assert_eq!(actual.depth, expected.depth, "{}", outcome.id);
                        let kinds = Encoding::ALL
                            .into_iter()
                            .filter(|encoding| actual.encodings & encoding.bit() != 0)
                            .map(|encoding| encoding.name().to_owned())
                            .collect::<Vec<_>>();
                        assert_eq!(kinds, expected.encoding_kinds, "{}", outcome.id);
                        assert_eq!(
                            expected.predecessor_indices,
                            (0..predecessors.len()).collect::<Vec<_>>(),
                            "{} pass {} segment {index}",
                            outcome.id,
                            pass_index + 1
                        );
                    }
                    assert_eq!(
                        tags(&segments)
                            .iter()
                            .map(|tag| base64::engine::general_purpose::STANDARD.encode(tag))
                            .collect::<Vec<_>>(),
                        expected.tags_base64,
                        "{} pass {}",
                        outcome.id,
                        expected.pass
                    );
                    assert_eq!(
                        current_line(&segments, &output),
                        oracle_bytes(&expected.current_line_base64),
                        "{} pass {}",
                        outcome.id,
                        expected.pass
                    );
                    for probe in &expected.probes {
                        assert_eq!(
                            adjust_match_index(&segments, probe.range[0], probe.range[1]),
                            Some((probe.adjusted[0], probe.adjusted[1])),
                            "{} pass {} probe {:?}",
                            outcome.id,
                            expected.pass,
                            probe.range
                        );
                        let overlapping = segments_with_decoded_overlap(
                            &segments,
                            probe.range[0],
                            probe.range[1],
                        );
                        let indices = overlapping
                            .iter()
                            .map(|selected| {
                                segments
                                    .iter()
                                    .position(|candidate| candidate == selected)
                                    .unwrap()
                            })
                            .collect::<Vec<_>>();
                        assert_eq!(
                            indices, probe.overlap_segment_indices,
                            "{} pass {} probe {:?}",
                            outcome.id, expected.pass, probe.range
                        );
                    }
                    current = output;
                    predecessors = segments;
                }
                assert_eq!(
                    rust_cache(decoder),
                    oracle_cache(&run.cache_after),
                    "{}",
                    outcome.id
                );
                assert_eq!(
                    current,
                    oracle_bytes(&run.full_decode_base64),
                    "{}",
                    outcome.id
                );
                assert_eq!(predecessors.is_empty(), run.terminated, "{}", outcome.id);
                if request.carry_predecessors_across_inputs {
                    carried_predecessors = predecessors;
                }
            }
        }
    }
}
