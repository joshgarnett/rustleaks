//! The production in-process Git parser with independently framed controls.

use rustleaks_sources::{CancellationToken, GitLimits, fuzz_parse_patch};

use super::campaign_profile::Profile;
use super::source_frame::{GitFrame, MAX_GIT_LINES, MAX_GIT_METADATA_BYTES, MAX_GIT_PATH_BYTES};

#[derive(Debug, Eq, PartialEq)]
pub struct Observation {
    /// The feature-gated parser hook exposes success counts or rejection only.
    /// `None` deliberately makes no claim about the internal error category.
    pub parsed: Option<(usize, usize)>,
    pub patch_bytes: usize,
}

pub fn exercise(data: &[u8], profile: Profile) -> Observation {
    let frame = GitFrame::decode(data, profile);
    let maximum = profile.input_limit("git_patch").expect("known target");
    let limits = GitLimits::new(maximum, MAX_GIT_LINES, 4 * 1024, maximum)
        .expect("fixed fuzz limits are positive")
        .with_parser_limits(
            MAX_GIT_METADATA_BYTES,
            MAX_GIT_PATH_BYTES,
            frame.controls.files,
            frame.controls.hunks,
        )
        .expect("derived parser limits are positive");
    let parse = || {
        let cancellation = CancellationToken::new();
        if frame.controls.cancel_before {
            cancellation.cancel();
        }
        fuzz_parse_patch(frame.patch, limits, &cancellation)
    };
    let parsed = parse();
    assert_eq!(parsed, parse(), "Git patch parsing must be deterministic");
    Observation {
        parsed,
        patch_bytes: frame.patch.len(),
    }
}
