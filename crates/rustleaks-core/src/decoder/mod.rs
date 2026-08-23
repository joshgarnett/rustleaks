//! Private encoded-segment decoder and original-offset mapper.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::convert::Infallible;
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

    fn decode(self, encoded: &[u8]) -> Vec<u8> {
        match self {
            Self::Percent => decode_percent(encoded),
            Self::Unicode => decode_unicode(encoded),
            Self::Hex => decode_hex(encoded),
            Self::Base64 => decode_base64(encoded),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EncodingMatch {
    encoding: Encoding,
    range: StartEnd,
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

    pub(crate) fn decode(
        &mut self,
        data: &[u8],
        predecessors: &[EncodedSegment],
    ) -> (Vec<u8>, Vec<EncodedSegment>) {
        match self.decode_controlled(data, predecessors, || Ok::<(), Infallible>(())) {
            Ok(decoded) => decoded,
            Err(never) => match never {},
        }
    }

    pub(crate) fn decode_controlled<E>(
        &mut self,
        data: &[u8],
        predecessors: &[EncodedSegment],
        mut checkpoint: impl FnMut() -> Result<(), E>,
    ) -> Result<(Vec<u8>, Vec<EncodedSegment>), E> {
        let segments = self.find_encoded_segments(data, predecessors, &mut checkpoint)?;
        if segments.is_empty() {
            return Ok((data.to_vec(), segments));
        }

        let mut result = Vec::with_capacity(data.len());
        let mut encoded_start = 0;
        for segment in &segments {
            checkpoint()?;
            let Some(encoded) = segment.encoded.as_usize() else {
                continue;
            };
            result.extend_from_slice(&data[encoded_start..encoded.start]);
            result.extend_from_slice(&segment.decoded_value);
            encoded_start = encoded.end;
        }
        result.extend_from_slice(&data[encoded_start..]);
        Ok((result, segments))
    }

    fn find_encoded_segments<E>(
        &mut self,
        data: &[u8],
        predecessors: &[EncodedSegment],
        checkpoint: &mut impl FnMut() -> Result<(), E>,
    ) -> Result<Vec<EncodedSegment>, E> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        let predecessor_depth = predecessors.first().map_or(0, |segment| segment.depth);
        let predecessor_snapshot: Arc<[EncodedSegment]> = Arc::from(predecessors);
        let mut decoded_shift = 0isize;
        let mut segments = Vec::new();
        for candidate in self.find_encoding_matches(data, checkpoint)? {
            checkpoint()?;
            let Some(encoded_range) = candidate.range.as_usize() else {
                continue;
            };
            let encoded_value = &data[encoded_range.clone()];
            let decoded_value = self
                .decoded
                .entry(encoded_value.to_vec())
                .or_insert_with(|| Arc::from(candidate.encoding.decode(encoded_value)))
                .clone();
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
            });
            decoded_shift += isize::try_from(decoded_value.len()).unwrap()
                - isize::try_from(encoded_value.len()).unwrap();
        }
        Ok(segments)
    }

    fn find_encoding_matches<E>(
        &self,
        data: &[u8],
        checkpoint: &mut impl FnMut() -> Result<(), E>,
    ) -> Result<Vec<EncodingMatch>, E> {
        let mut all = Vec::new();
        for captures in self.encodings.captures_all(data) {
            checkpoint()?;
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

pub(crate) fn segments_with_decoded_overlap(
    segments: &[EncodedSegment],
    start: usize,
    end: usize,
) -> Vec<EncodedSegment> {
    let range = StartEnd {
        start: isize::try_from(start).unwrap(),
        end: isize::try_from(end).unwrap(),
    };
    segments
        .iter()
        .filter(|segment| segment.decoded.overlaps(range))
        .cloned()
        .collect()
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

pub(crate) fn current_line<'a>(segments: &[EncodedSegment], current_raw: &'a [u8]) -> &'a [u8] {
    if segments.is_empty() {
        return current_raw;
    }
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
        .find(|&index| current_raw[index] == b'\n')
        .unwrap_or(0);
    let end = (decoded_end..current_raw.len())
        .find(|&index| current_raw[index] == b'\n')
        .unwrap_or(current_raw.len());
    &current_raw[start..end]
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

fn decode_percent(encoded: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::with_capacity(encoded.len());
    let mut index = 0;
    while index < encoded.len() {
        if encoded[index] == b'%' && index + 2 < encoded.len() {
            if let (Some(high), Some(low)) = (
                hex_nibble(encoded[index + 1]),
                hex_nibble(encoded[index + 2]),
            ) {
                let byte = (high << 4) | low;
                if !is_printable_ascii(byte) {
                    return Vec::new();
                }
                decoded.push(byte);
                index += 3;
                continue;
            }
        }
        decoded.push(encoded[index]);
        index += 1;
    }
    decoded
}

fn decode_hex(encoded: &[u8]) -> Vec<u8> {
    if encoded.len() % 2 != 0 || !encoded.iter().any(u8::is_ascii_digit) {
        return Vec::new();
    }
    let mut decoded = Vec::with_capacity(encoded.len() / 2);
    for pair in encoded.chunks_exact(2) {
        let (Some(high), Some(low)) = (hex_nibble(pair[0]), hex_nibble(pair[1])) else {
            return Vec::new();
        };
        let byte = (high << 4) | low;
        if !is_printable_ascii(byte) {
            return Vec::new();
        }
        decoded.push(byte);
    }
    decoded
}

fn decode_base64(encoded: &[u8]) -> Vec<u8> {
    if !encoded
        .iter()
        .any(|byte| matches!(byte, b'0'..=b'9' | b'+' | b'/' | b'-' | b'_'))
    {
        return Vec::new();
    }
    for engine in [&GO_STANDARD_BASE64, &GO_RAW_URL_BASE64] {
        if let Ok(decoded) = engine.decode(encoded) {
            if decoded.iter().copied().all(is_printable_ascii) {
                return decoded;
            }
        }
    }
    Vec::new()
}

fn decode_unicode(encoded: &[u8]) -> Vec<u8> {
    if encoded.starts_with(b"U+") {
        return encoded
            .split(u8::is_ascii_whitespace)
            .filter(|field| !field.is_empty())
            .filter_map(|field| field.strip_prefix(b"U+"))
            .filter(|digits| digits.len() >= 4)
            .fold(Vec::new(), |mut decoded, digits| {
                push_unicode_escape(&mut decoded, &digits[..4]);
                decoded
            });
    }

    let mut decoded = Vec::new();
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
        push_unicode_escape(&mut decoded, digits);
        index = digits_start + 4;
    }
    decoded
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
