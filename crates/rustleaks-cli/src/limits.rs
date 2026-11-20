//! Numeric scan limits from the command line, converted and checked once.

use std::time::Duration;

use crate::args::Options;

/// Bytes in one megabyte for `--max-target-megabytes`.
const MEGABYTE: u64 = 1_000_000;

/// The size and depth limits of one scan.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ScanLimits {
    /// Largest file that a source reads, in bytes. `None` means no limit.
    pub source_max: Option<u64>,
    /// Largest fragment that the engine scans, in bytes. It is 999,999 bytes
    /// more than `source_max`. `None` means no limit.
    pub engine_max: Option<usize>,
    /// How many levels of encoded text the engine decodes.
    pub decode_depth: usize,
    /// How many levels of nested archives a source opens. 0 means that
    /// archives are not opened.
    pub archive_depth: usize,
}

impl ScanLimits {
    /// Converts the numeric flags. A value of 0 or below means no limit for
    /// sizes and no decoding or archive reading for depths.
    pub(crate) fn from_options(options: &Options) -> Result<Self, String> {
        let (source_max, engine_max) = if options.max_target_megabytes > 0 {
            let too_large = || "--max-target-megabytes is out of range".to_owned();
            let megabytes = u64::try_from(options.max_target_megabytes).map_err(|_| too_large())?;
            let source = megabytes.checked_mul(MEGABYTE).ok_or_else(too_large)?;
            let engine = megabytes
                .checked_add(1)
                .and_then(|value| value.checked_mul(MEGABYTE))
                .and_then(|value| value.checked_sub(1))
                .and_then(|value| usize::try_from(value).ok())
                .ok_or_else(too_large)?;
            (Some(source), Some(engine))
        } else {
            (None, None)
        };
        Ok(Self {
            source_max,
            engine_max,
            decode_depth: depth("--max-decode-depth", options.max_decode_depth)?,
            archive_depth: depth("--max-archive-depth", options.max_archive_depth)?,
        })
    }
}

fn depth(name: &str, value: i64) -> Result<usize, String> {
    if value <= 0 {
        return Ok(0);
    }
    usize::try_from(value).map_err(|_| format!("{name} is out of range"))
}

/// The `--timeout` duration. A value of 0 or below means no time limit.
pub(crate) fn timeout(options: &Options) -> Option<Duration> {
    u64::try_from(options.timeout_seconds)
        .ok()
        .filter(|seconds| *seconds > 0)
        .map(Duration::from_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(max_target_megabytes: i64) -> Result<ScanLimits, String> {
        ScanLimits::from_options(&Options {
            max_target_megabytes,
            ..Options::default()
        })
    }

    #[test]
    fn megabyte_limits_differ_for_sources_and_the_engine() {
        let two = limits(2).unwrap();
        assert_eq!(two.source_max, Some(2_000_000));
        assert_eq!(two.engine_max, Some(2_999_999));
        for value in [0, -1, i64::MIN] {
            let none = limits(value).unwrap();
            assert_eq!((none.source_max, none.engine_max), (None, None));
        }
    }

    #[test]
    fn megabyte_overflow_is_one_error() {
        assert_eq!(
            limits(i64::MAX).unwrap_err(),
            "--max-target-megabytes is out of range"
        );
    }

    #[test]
    fn depths_below_one_turn_the_feature_off() {
        let options = Options {
            max_decode_depth: -3,
            max_archive_depth: 4,
            ..Options::default()
        };
        let limits = ScanLimits::from_options(&options).unwrap();
        assert_eq!((limits.decode_depth, limits.archive_depth), (0, 4));
        assert_eq!(
            ScanLimits::from_options(&Options::default())
                .unwrap()
                .decode_depth,
            5
        );
    }

    #[test]
    fn timeouts_of_zero_or_below_are_no_limit() {
        for (seconds, expected) in [(0, None), (-5, None), (7, Some(Duration::from_secs(7)))] {
            let options = Options {
                timeout_seconds: seconds,
                ..Options::default()
            };
            assert_eq!(timeout(&options), expected);
        }
    }
}
