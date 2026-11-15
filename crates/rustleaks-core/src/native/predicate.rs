//! Bounded, versioned predicates over the already selected secret capture.

use base64::Engine as _;
use base64::alphabet::STANDARD;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};

use crate::regex::GoRegex;

use super::{NativePolicyError, native_fields};

pub(crate) mod vercel;

pub(crate) const MAX_ENCODED_BYTES: usize = 308;
pub(crate) const MAX_DECODED_BYTES: usize = 231;
const SEGMENT_BASE64: GeneralPurpose = GeneralPurpose::new(
    &STANDARD,
    GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum NativePredicate {
    Base64UrlSegment(Base64UrlSegment),
    VercelCl100kRatio,
}

impl NativePredicate {
    pub(crate) fn algorithm(&self) -> &'static str {
        match self {
            Self::Base64UrlSegment(_) => "base64url-segment-go-regex-v1",
            Self::VercelCl100kRatio => "vercel-cl100k-ratio-v1",
        }
    }

    pub(crate) fn retained_bytes(&self) -> usize {
        self.algorithm().len()
            + match self {
                Self::Base64UrlSegment(predicate) => predicate.pattern.len() + 6 * 8 + 1,
                Self::VercelCl100kRatio => 0,
            }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Base64UrlSegment {
    encoded_min: usize,
    encoded_max: usize,
    decoded_max: usize,
    pattern: String,
    pub(crate) matcher: GoRegex,
}

impl Base64UrlSegment {
    /// Malformed candidates reject locally. Aggregate scan limits are handled
    /// by the caller and must never be translated into candidate rejection.
    pub(crate) fn decode<'a>(
        &self,
        secret: &[u8],
        output: &'a mut [u8; MAX_DECODED_BYTES],
    ) -> Option<&'a [u8]> {
        // Bound structural scanning even for a custom outer capture. The
        // source's two-byte prefix and 22-byte signature fit comfortably.
        if secret.len() > 3 * MAX_ENCODED_BYTES + 2 {
            return None;
        }
        // Find only the first two separators. Reject a third without retaining
        // any fragment-sized scratch or a collection of segments.
        let first = secret.iter().position(|byte| *byte == b'.')?;
        let rest = &secret[first + 1..];
        let second = rest.iter().position(|byte| *byte == b'.')?;
        if rest[second + 1..].contains(&b'.') {
            return None;
        }
        let encoded = &rest[..second];
        if !(self.encoded_min..=self.encoded_max).contains(&encoded.len()) || encoded.len() % 4 == 1
        {
            return None;
        }
        let mut padded = [b'='; MAX_ENCODED_BYTES];
        for (&byte, slot) in encoded.iter().zip(&mut padded) {
            *slot = match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' => byte,
                b'-' => b'+',
                b'_' => b'/',
                _ => return None,
            };
        }
        let padded_len = encoded.len().div_ceil(4) * 4;
        let length = SEGMENT_BASE64
            .decode_slice(&padded[..padded_len], output)
            .ok()?;
        let decoded = output
            .get(..length)
            .filter(|bytes| bytes.len() <= self.decoded_max)?;
        std::str::from_utf8(decoded).ok()?;
        Some(decoded)
    }
}

pub(super) fn parse(value: &toml::Value) -> Result<NativePredicate, NativePolicyError> {
    if !value.is_table() {
        return Err(NativePolicyError::InvalidNativePredicate);
    }
    let fields = native_fields(
        value,
        &[
            "algorithm",
            "parts",
            "separator",
            "segment",
            "encodedmin",
            "encodedmax",
            "decodedmax",
            "regex",
        ],
    )?;
    match fields.get("algorithm").and_then(|value| value.as_str()) {
        Some("vercel-cl100k-ratio-v1") if fields.len() == 1 => {
            Ok(NativePredicate::VercelCl100kRatio)
        }
        Some("base64url-segment-go-regex-v1") if fields.len() == 8 => {
            let integer = |name: &str| -> Result<usize, NativePolicyError> {
                fields
                    .get(name)
                    .and_then(|value| value.as_integer())
                    .and_then(|value| usize::try_from(value).ok())
                    .ok_or(NativePolicyError::InvalidNativePredicate)
            };
            let encoded_min = integer("encodedmin")?;
            let encoded_max = integer("encodedmax")?;
            let decoded_max = integer("decodedmax")?;
            if integer("parts")? != 3
                || integer("segment")? != 1
                || fields.get("separator").and_then(|value| value.as_str()) != Some(".")
                || encoded_min == 0
                || encoded_min > encoded_max
                || encoded_max > MAX_ENCODED_BYTES
                || decoded_max == 0
                || decoded_max > MAX_DECODED_BYTES
            {
                return Err(NativePolicyError::InvalidNativePredicate);
            }
            let pattern = fields
                .get("regex")
                .and_then(|value| value.as_str())
                .filter(|pattern| !pattern.is_empty())
                .ok_or(NativePolicyError::InvalidNativePredicate)?;
            // Require a whole decoded payload match, including when callers use
            // alternation or multiline flags. Existing GoRegex limits still apply.
            let matcher = GoRegex::compile_whole(pattern)
                .map_err(|_| NativePolicyError::InvalidNativePredicate)?;
            Ok(NativePredicate::Base64UrlSegment(Base64UrlSegment {
                encoded_min,
                encoded_max,
                decoded_max,
                pattern: pattern.to_owned(),
                matcher,
            }))
        }
        _ => Err(NativePolicyError::InvalidNativePredicate),
    }
}

pub(super) fn extract(
    value: &mut toml::Value,
) -> Result<Vec<Option<NativePredicate>>, NativePolicyError> {
    fn rule(value: &mut toml::Value) -> Result<Option<NativePredicate>, NativePolicyError> {
        let table = value
            .as_table_mut()
            .ok_or(NativePolicyError::InvalidPackStructure)?;
        let Some(key) = table
            .keys()
            .find(|key| key.eq_ignore_ascii_case("predicate"))
            .cloned()
        else {
            return Ok(None);
        };
        // A valid descriptor must fail closed through the ordinary loader.
        // Typed byte regexes cannot deserialize as legacy string regexes.
        let regex = table
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case("regex"))
            .map(|(_, value)| value)
            .ok_or(NativePolicyError::InvalidNativePredicate)?;
        if !regex.is_table() || super::parse_native_regex(regex)?.is_empty() {
            return Err(NativePolicyError::InvalidNativePredicate);
        }
        let value = table
            .remove(&key)
            .ok_or(NativePolicyError::InvalidNativePredicate)?;
        Ok(Some(parse(&value)?))
    }
    let table = value
        .as_table_mut()
        .ok_or(NativePolicyError::InvalidPackStructure)?;
    let Some((_, rules)) = table
        .iter_mut()
        .find(|(key, _)| key.eq_ignore_ascii_case("rules"))
    else {
        return Ok(Vec::new());
    };
    match rules {
        toml::Value::Array(rules) => rules.iter_mut().map(rule).collect(),
        toml::Value::Table(table) if table.is_empty() => Ok(Vec::new()),
        value => Ok(vec![rule(value)?]),
    }
}

#[cfg(test)]
mod tests;
