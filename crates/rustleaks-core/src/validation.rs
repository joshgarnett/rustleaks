//! Allowlisted, offline structural assessments with no finding suppression.
//!
//! These checks never contact an issuer or establish activation, expiry,
//! revocation, or safety. A positive layout result is distinct from a checksum
//! result. Unsupported formats remain unknown rather than being called safe.

use serde::Serialize;

use crate::explanation::{ValidationReason, ValidationState};

/// Versioned structural check whose result is being reported.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OfflineCheck {
    /// Historical 40-byte classic PAT layout only, not checksum or activation.
    GithubClassicPatLayoutV1,
    /// Historical checksum assessment, currently unknown because issuer
    /// documentation does not fully specify reproducible checksum parameters.
    GithubClassicPatChecksumV1,
}

/// Source-omitting result of one explicitly identified offline check.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct OfflineAssessment {
    check: OfflineCheck,
    state: ValidationState,
    reason: ValidationReason,
}

impl OfflineAssessment {
    /// Returns the exact structural check evaluated.
    #[must_use]
    pub const fn check(self) -> OfflineCheck {
        self.check
    }

    /// Returns structural validity or uncertainty for this check alone.
    #[must_use]
    pub const fn state(self) -> ValidationState {
        self.state
    }

    /// Returns the decision's finite reason code.
    #[must_use]
    pub const fn reason(self) -> ValidationReason {
        self.reason
    }
}

/// Assesses the historical `ghp_` 40-byte layout and its checksum separately.
///
/// Exact-prefix, exact-length candidates with 36 ASCII alphanumeric body bytes
/// have a valid historical layout. Within that exact scope, other body bytes
/// violate its alphabet. Other prefixes or lengths, including truncated, older
/// hexadecimal, fine-grained, and newer installation tokens, remain unknown.
/// A malformed layout remains potential exposure evidence.
///
/// Checksum is always unknown: GitHub's published description does not specify
/// the CRC variant, hashed portion, and Base62 alphabet ordering precisely
/// enough for this implementation to assert checksum validity. See the
/// repository's offline-validation source review. Both results omit input bytes.
/// The operation examines at most 40 bytes and allocates nothing.
#[must_use]
pub fn github_classic_pat(candidate: &[u8]) -> [OfflineAssessment; 2] {
    let in_scope = candidate.len() == 40 && candidate.starts_with(b"ghp_");
    let (state, reason) = if !in_scope {
        (
            ValidationState::Unknown,
            ValidationReason::UnsupportedFormat,
        )
    } else if candidate[4..].iter().all(u8::is_ascii_alphanumeric) {
        (
            ValidationState::Valid,
            ValidationReason::HistoricalLayoutMatched,
        )
    } else {
        (
            ValidationState::Invalid,
            ValidationReason::HistoricalAlphabetMismatch,
        )
    };
    [
        OfflineAssessment {
            check: OfflineCheck::GithubClassicPatLayoutV1,
            state,
            reason,
        },
        OfflineAssessment {
            check: OfflineCheck::GithubClassicPatChecksumV1,
            state: ValidationState::Unknown,
            reason: if in_scope {
                ValidationReason::UnspecifiedChecksumContract
            } else {
                ValidationReason::UnsupportedFormat
            },
        },
    ]
}

pub(crate) fn github_classic_pat_in_context(
    candidate: &[u8],
    isolated: bool,
) -> [OfflineAssessment; 2] {
    let mut assessments = github_classic_pat(candidate);
    if !isolated {
        for assessment in &mut assessments {
            assessment.state = ValidationState::Unknown;
            assessment.reason = ValidationReason::AmbiguousBoundary;
        }
    }
    assessments
}
