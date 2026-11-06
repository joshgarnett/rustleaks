//! Versioned optional campaign policy; ordinary smoke defaults remain unchanged.

use serde_json::{Value, json};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Profile {
    Smoke,
    Extended,
    Deep,
}
impl Profile {
    pub(crate) fn parse(value: &str) -> Result<Self, String> {
        match value {
            "smoke" => Ok(Self::Smoke),
            "extended" => Ok(Self::Extended),
            "deep" => Ok(Self::Deep),
            _ => Err("profile must be smoke, extended or deep".into()),
        }
    }
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Smoke => "smoke",
            Self::Extended => "extended",
            Self::Deep => "deep",
        }
    }
    pub(crate) fn seconds(self) -> u64 {
        match self {
            Self::Smoke => 20,
            Self::Extended => 120,
            Self::Deep => 600,
        }
    }
    pub(crate) fn runs(self) -> u64 {
        if self == Self::Smoke { 16 } else { 1_000_000 }
    }
    pub(crate) fn maximum_input(self, target: &str) -> Result<u64, String> {
        let profile = if self == Self::Deep {
            super::campaign_profile::Profile::Deep
        } else {
            super::campaign_profile::Profile::Smoke
        };
        profile
            .input_limit(target)
            .map(|limit| limit as u64)
            .ok_or_else(|| "unknown fuzz target".into())
    }
    pub(crate) fn record(self) -> Value {
        let harness = if self == Self::Deep {
            super::campaign_profile::Profile::Deep
        } else {
            super::campaign_profile::Profile::Smoke
        };
        let archive = harness.archive();
        let fragment = harness.fragment();
        let template = harness.template();
        json!({"name":self.name(),"version":1,"harness":if self==Self::Deep {"deep"}else{"smoke"},
            "archive":{"depth":archive.depth,"entries":archive.entries,"member_bytes":archive.member_bytes,"total_bytes":archive.total_bytes,"input_and_spool_bytes":archive.input_bytes,"chunk_bytes":archive.chunk_bytes},
            "fragment":{"input_bytes":fragment.input_bytes,"decode_depth":fragment.decode_depth,"decoded_bytes":fragment.decoded_bytes,"work_units":fragment.work_units,"finding_records":fragment.finding_records},
            "template":{"input_bytes":template.input_bytes,"source_bytes":template.source_bytes,"actions":template.actions,"output_bytes":template.output_bytes,"findings":template.findings}})
    }
    pub(super) fn from_record(value: &Value) -> Result<Self, String> {
        if value.is_null() {
            return Ok(Self::Smoke);
        }
        let profile = Self::parse(value["name"].as_str().ok_or("missing campaign profile")?)?;
        if *value != profile.record() {
            return Err("campaign profile policy is incompatible".into());
        }
        Ok(profile)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Deadline {
    until: Option<Instant>,
}
impl Deadline {
    pub(crate) fn new(seconds: Option<u64>) -> Self {
        Self {
            until: seconds.map(|value| Instant::now() + Duration::from_secs(value)),
        }
    }
    pub(crate) fn remaining(self, maximum: Duration) -> Result<Duration, String> {
        match self.until {
            None => Ok(maximum),
            Some(until) => until
                .checked_duration_since(Instant::now())
                .filter(|value| !value.is_zero())
                .map(|value| value.min(maximum))
                .ok_or_else(|| "whole-run deadline exhausted".into()),
        }
    }
    pub(crate) fn snapshot(self) -> Value {
        let remaining = self
            .until
            .map(|until| until.saturating_duration_since(Instant::now()));
        json!({"bounded":self.until.is_some(),"remaining_ns":remaining.map(|value|value.as_nanos())})
    }

    /// The returned duration is the exact timeout supplied to the child supervisor.
    pub(crate) fn supervisor(self, maximum: Duration) -> (Duration, Value) {
        let remaining = self
            .until
            .map(|until| until.saturating_duration_since(Instant::now()));
        let effective = remaining.map_or(maximum, |value| value.min(maximum));
        let record = json!({"requested_maximum_ms":maximum.as_millis(),
            "effective_timeout_ms":effective.as_millis(),"effective_timeout_ns":effective.as_nanos(),
            "operation_remaining_ns_at_selection":remaining.map(|value|value.as_nanos()),
            "deadline_constrained":remaining.is_some_and(|value|value<maximum),
            "cleanup_grace_ms":5000,"clock":"monotonic; selected before child launch"});
        (effective, record)
    }

    pub(crate) fn intersect(self, other: Self) -> Self {
        Self {
            until: match (self.until, other.until) {
                (Some(left), Some(right)) => Some(left.min(right)),
                (Some(until), None) | (None, Some(until)) => Some(until),
                (None, None) => None,
            },
        }
    }
    pub(crate) fn expired(self) -> bool {
        self.remaining(Duration::from_secs(1)).is_err()
    }
}

pub(crate) fn bounded(value: &str, maximum: u64, field: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0 && *value <= maximum)
        .ok_or_else(|| format!("{field} must be in 1..={maximum}"))
}
pub(crate) fn targets(value: &str) -> Result<Vec<String>, String> {
    let mut selected = Vec::new();
    for name in value.split(',') {
        if !super::TARGETS.iter().any(|target| target.name == name)
            || selected.iter().any(|old| old == name)
        {
            return Err("unknown or duplicate fuzz target".into());
        }
        selected.push(name.to_owned());
    }
    Ok(selected)
}
