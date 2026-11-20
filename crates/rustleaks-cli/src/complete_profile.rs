//! Explicit, bounded complete-target CLI policy. This format is not TOML.

use std::fs::File;
use std::io::{self, Read, Write};
use std::num::NonZeroUsize;
use std::path::Path;

use rustleaks_core::ScanBudget;
use rustleaks_sources::{
    ArchiveLimits, FileOptions, GitLimits, SourceBudget, SourceBudgetKind, SourceBudgetScope,
    SourceOutcome, SourceRunner, SourceTermination, SourceUsage,
};

use crate::args::{CommandKind, Invocation};

const MAX_PROFILE_BYTES: usize = 16 * 1024;
// Version 1 bounds waiting fragments and requested detection threads.
// These are scheduling guards, not a process memory quota.
const MAX_WORKERS: usize = 64;
const MAX_QUEUE_CAPACITY: usize = 1024;
const KEYS: &[&str] = &[
    "version",
    "target_bytes",
    "operation_original_bytes",
    "operation_fragments",
    "operation_issues",
    "workers",
    "queue_capacity",
    "fragment_decoded_bytes",
    "operation_decoded_bytes",
    "fragment_work_units",
    "operation_work_units",
    "fragment_finding_records",
    "operation_finding_records",
    "fragment_finding_payload_bytes",
    "operation_finding_payload_bytes",
    "fragment_collected_spans",
    "operation_collected_spans",
    "fragment_normalization_bytes",
    "operation_normalization_bytes",
    "archive_entries",
    "archive_member_bytes",
    "archive_total_bytes",
    "archive_spool_bytes",
    "git_patch_bytes",
    "git_patch_lines",
    "git_stderr_bytes",
    "git_blob_bytes",
    "git_metadata_bytes",
    "git_path_bytes",
    "git_files",
    "git_hunks",
    "scm_link_bytes",
    "operation_scm_link_bytes",
];

#[derive(Clone, Debug)]
pub(crate) struct CompleteProfile {
    pub target_bytes: usize,
    pub operation_original_bytes: usize,
    pub operation_fragments: usize,
    pub operation_issues: usize,
    pub workers: usize,
    pub queue_capacity: usize,
    pub fragment_decoded_bytes: usize,
    pub operation_decoded_bytes: usize,
    pub fragment_work_units: usize,
    pub operation_work_units: usize,
    pub fragment_finding_records: usize,
    pub operation_finding_records: usize,
    pub fragment_finding_payload_bytes: usize,
    pub operation_finding_payload_bytes: usize,
    pub fragment_collected_spans: usize,
    pub operation_collected_spans: usize,
    pub fragment_normalization_bytes: usize,
    pub operation_normalization_bytes: usize,
    pub archive_entries: usize,
    pub archive_member_bytes: usize,
    pub archive_total_bytes: usize,
    pub archive_spool_bytes: usize,
    // The patch byte, patch line, metadata, file and hunk keys are limits for
    // one commit. Git history is streamed, so no key limits its total size.
    pub git_patch_bytes: usize,
    pub git_patch_lines: usize,
    pub git_stderr_bytes: usize,
    pub git_blob_bytes: usize,
    pub git_metadata_bytes: usize,
    pub git_path_bytes: usize,
    pub git_files: usize,
    pub git_hunks: usize,
    pub scm_link_bytes: usize,
    pub operation_scm_link_bytes: usize,
}

impl CompleteProfile {
    pub fn load(path: &Path) -> Result<Self, String> {
        let file = File::open(path).map_err(|_| "could not open complete profile".to_owned())?;
        Self::read(file)
    }

    fn read(mut reader: impl Read) -> Result<Self, String> {
        // No buffered reader: every underlying request ends at the cap plus
        // one, including a reader that produces an error after earlier data.
        let mut bytes = vec![0_u8; MAX_PROFILE_BYTES + 1].into_boxed_slice();
        let mut length = 0;
        loop {
            if length == bytes.len() {
                return Err(format!(
                    "complete profile exceeds {MAX_PROFILE_BYTES} bytes"
                ));
            }
            match reader.read(&mut bytes[length..]) {
                Ok(0) => return Self::parse(&bytes[..length]),
                Ok(read) if read <= bytes.len() - length => length += read,
                Ok(_) => return Err("complete profile reader overreported its count".to_owned()),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return Err("could not read complete profile".to_owned()),
            }
        }
    }

    fn parse(bytes: &[u8]) -> Result<Self, String> {
        if !bytes.is_ascii() {
            return Err("complete profile must contain ASCII only".to_owned());
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| "complete profile must contain ASCII only".to_owned())?;
        let mut values = [None; KEYS.len()];
        for (line_index, line) in text.lines().enumerate() {
            let line = line.trim_matches([' ', '\t', '\r']);
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let invalid = || format!("invalid complete profile field on line {}", line_index + 1);
            let (key, value) = line.split_once('=').ok_or_else(invalid)?;
            let key = key.trim_matches([' ', '\t']);
            let value = value.trim_matches([' ', '\t']);
            let index = KEYS
                .iter()
                .position(|known| *known == key)
                .ok_or_else(invalid)?;
            if values[index].is_some()
                || value.is_empty()
                || !value.bytes().all(|b| b.is_ascii_digit())
            {
                return Err(invalid());
            }
            let parsed = value.parse::<u64>().map_err(|_| invalid())?;
            values[index] = Some(usize::try_from(parsed).map_err(|_| invalid())?);
        }
        for (key, value) in KEYS.iter().zip(values) {
            if value.is_none() {
                return Err(format!("missing complete profile field: {key}"));
            }
        }
        let values = values.map(|value| value.expect("all required fields were checked"));
        if values[0] != 1 {
            return Err("unsupported complete profile version".to_owned());
        }
        for index in [
            1, 5, 6, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
        ] {
            if values[index] == 0 {
                return Err(format!(
                    "complete profile field {} must be positive",
                    KEYS[index]
                ));
            }
        }
        for (index, maximum) in [(5, MAX_WORKERS), (6, MAX_QUEUE_CAPACITY)] {
            if values[index] > maximum {
                return Err(format!(
                    "complete profile field {} exceeds maximum {maximum}",
                    KEYS[index]
                ));
            }
        }
        Ok(Self {
            target_bytes: values[1],
            operation_original_bytes: values[2],
            operation_fragments: values[3],
            operation_issues: values[4],
            workers: values[5],
            queue_capacity: values[6],
            fragment_decoded_bytes: values[7],
            operation_decoded_bytes: values[8],
            fragment_work_units: values[9],
            operation_work_units: values[10],
            fragment_finding_records: values[11],
            operation_finding_records: values[12],
            fragment_finding_payload_bytes: values[13],
            operation_finding_payload_bytes: values[14],
            fragment_collected_spans: values[15],
            operation_collected_spans: values[16],
            fragment_normalization_bytes: values[17],
            operation_normalization_bytes: values[18],
            archive_entries: values[19],
            archive_member_bytes: values[20],
            archive_total_bytes: values[21],
            archive_spool_bytes: values[22],
            git_patch_bytes: values[23],
            git_patch_lines: values[24],
            git_stderr_bytes: values[25],
            git_blob_bytes: values[26],
            git_metadata_bytes: values[27],
            git_path_bytes: values[28],
            git_files: values[29],
            git_hunks: values[30],
            scm_link_bytes: values[31],
            operation_scm_link_bytes: values[32],
        })
    }

    pub fn validate_invocation(invocation: &Invocation) -> Result<(), String> {
        if invocation.options.max_target_megabytes > 0 {
            return Err(
                "--complete-profile cannot be combined with positive --max-target-megabytes"
                    .to_owned(),
            );
        }
        if invocation.options.exit_code == 2 {
            return Err(
                "--exit-code 2 is reserved for incomplete complete-profile scans".to_owned(),
            );
        }
        Ok(())
    }

    pub fn file_options(&self) -> Result<FileOptions, String> {
        FileOptions::complete(self.target_bytes).map_err(|error| error.to_string())
    }

    pub fn archive_limits(&self, depth: usize) -> Result<ArchiveLimits, String> {
        ArchiveLimits::new(
            depth,
            self.archive_entries,
            self.archive_member_bytes,
            self.archive_total_bytes,
            self.archive_spool_bytes,
        )
        .map_err(|error| error.to_string())
    }

    pub fn git_limits(&self) -> Result<GitLimits, String> {
        GitLimits::new(
            self.git_patch_bytes,
            self.git_patch_lines,
            self.git_stderr_bytes,
            self.git_blob_bytes,
        )
        .and_then(|limits| {
            limits.with_parser_limits(
                self.git_metadata_bytes,
                self.git_path_bytes,
                self.git_files,
                self.git_hunks,
            )
        })
        .map_err(|error| error.to_string())
    }

    /// Builds the profile runner. `--jobs`, when given, replaces the profile
    /// `workers` value; the queue capacity always comes from the profile.
    pub fn runner(&self, jobs: Option<NonZeroUsize>) -> Result<SourceRunner, String> {
        let fragment = ScanBudget::unlimited()
            .max_decoded_bytes(self.fragment_decoded_bytes)
            .max_work_units(self.fragment_work_units)
            .max_finding_records(self.fragment_finding_records)
            .max_finding_payload_bytes(self.fragment_finding_payload_bytes)
            .max_collected_spans(self.fragment_collected_spans)
            .max_normalization_bytes(self.fragment_normalization_bytes);
        let operation = ScanBudget::unlimited()
            .max_decoded_bytes(self.operation_decoded_bytes)
            .max_work_units(self.operation_work_units)
            .max_finding_records(self.operation_finding_records)
            .max_finding_payload_bytes(self.operation_finding_payload_bytes)
            .max_collected_spans(self.operation_collected_spans)
            .max_normalization_bytes(self.operation_normalization_bytes);
        let workers = jobs.map_or(self.workers, NonZeroUsize::get);
        SourceRunner::new(workers, self.queue_capacity)
            .map_err(|error| error.to_string())?
            .fail_on_coverage_error(true)
            .with_budget(
                SourceBudget::unlimited()
                    .max_fragment_bytes(self.target_bytes)
                    .max_original_bytes(self.operation_original_bytes)
                    .max_fragments(self.operation_fragments)
                    .max_issues(self.operation_issues)
                    .per_fragment(fragment)
                    .aggregate(operation),
            )
            .map_err(|error| error.to_string())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CompletionReason {
    Complete,
    ProfileError,
    SetupFailure,
    CoverageFailure,
    ResourceExhaustion,
    Cancelled,
    WorkerFailure,
    MetadataFailure,
    ReportFailure,
    Stopped,
    UnknownTermination,
}

impl CompletionReason {
    const fn name(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::ProfileError => "profile_error",
            Self::SetupFailure => "setup_failure",
            Self::CoverageFailure => "coverage_failure",
            Self::ResourceExhaustion => "resource_exhaustion",
            Self::Cancelled => "cancelled",
            Self::WorkerFailure => "worker_failure",
            Self::MetadataFailure => "metadata_failure",
            Self::ReportFailure => "report_failure",
            Self::Stopped => "stopped",
            Self::UnknownTermination => "unknown_termination",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct LimitFailure {
    resource: &'static str,
    scope: &'static str,
    limit: usize,
    consumed: usize,
    requested: usize,
}

pub(crate) struct CompletionStatus {
    pub reason: CompletionReason,
    usage: Option<SourceUsage>,
    failure: Option<LimitFailure>,
    scm_link_bytes: usize,
    findings: usize,
    issues: usize,
}

impl Default for CompletionStatus {
    fn default() -> Self {
        Self {
            reason: CompletionReason::SetupFailure,
            usage: None,
            failure: None,
            scm_link_bytes: 0,
            findings: 0,
            issues: 0,
        }
    }
}

impl CompletionStatus {
    pub fn observe(&mut self, outcome: &SourceOutcome) {
        self.usage = outcome.usage();
        self.issues = outcome.issues().len();
        self.findings = outcome.findings().len();
        self.reason = match outcome.termination() {
            SourceTermination::Completed => CompletionReason::Complete,
            SourceTermination::Stopped => CompletionReason::Stopped,
            SourceTermination::Cancelled => CompletionReason::Cancelled,
            SourceTermination::WorkerPanic => CompletionReason::WorkerFailure,
            SourceTermination::SourceError(rustleaks_sources::SourceError::Terminal {
                stage: rustleaks_sources::SourceStage::Limit,
                ..
            }) => CompletionReason::ResourceExhaustion,
            SourceTermination::SourceError(rustleaks_sources::SourceError::Cancelled) => {
                CompletionReason::Cancelled
            }
            SourceTermination::SourceError(_) => CompletionReason::CoverageFailure,
            SourceTermination::BudgetExceeded(exceeded) => {
                self.failure = Some(LimitFailure {
                    resource: resource_name(exceeded.kind()),
                    scope: match exceeded.scope() {
                        SourceBudgetScope::Fragment => "fragment",
                        SourceBudgetScope::Operation => "operation",
                    },
                    limit: exceeded.limit(),
                    consumed: exceeded.consumed(),
                    requested: exceeded.requested(),
                });
                CompletionReason::ResourceExhaustion
            }
            _ => CompletionReason::UnknownTermination,
        };
    }

    pub const fn is_complete(&self) -> bool {
        matches!(self.reason, CompletionReason::Complete)
    }

    pub fn admit_link(&mut self, profile: &CompleteProfile, length: usize) -> bool {
        for (scope, limit, consumed) in [
            ("link", profile.scm_link_bytes, 0),
            (
                "operation",
                profile.operation_scm_link_bytes,
                self.scm_link_bytes,
            ),
        ] {
            if length > limit.saturating_sub(consumed) {
                self.reason = CompletionReason::MetadataFailure;
                self.failure = Some(LimitFailure {
                    resource: "scm_link_bytes",
                    scope,
                    limit,
                    consumed,
                    requested: length,
                });
                return false;
            }
        }
        // Admission checked both the remaining allowance and representable sum.
        self.scm_link_bytes += length;
        true
    }

    pub fn write(&self, invocation: &Invocation, writer: &mut dyn Write) -> io::Result<()> {
        let state = if self.is_complete() {
            "complete"
        } else {
            "incomplete"
        };
        let scope = match invocation.command {
            CommandKind::Directory => "directory_targets",
            CommandKind::Stdin => "stdin_targets",
            CommandKind::Git => "git_additions_and_archive_leaves",
        };
        write!(
            writer,
            "rustleaks_scan_status version=1 status={state} reason={} source_scope={scope} findings={} reports={} decode_depth={} archive_depth={}",
            self.reason.name(),
            self.findings,
            if self.is_complete() {
                "complete"
            } else {
                "partial"
            },
            invocation.options.max_decode_depth.max(0),
            invocation.options.max_archive_depth.max(0)
        )?;
        if let Some(failure) = self.failure {
            write!(
                writer,
                " resource={} budget_scope={} limit={} consumed={} requested={}",
                failure.resource, failure.scope, failure.limit, failure.consumed, failure.requested
            )?;
        } else {
            write!(
                writer,
                " resource=none budget_scope=none limit=none consumed=none requested=none"
            )?;
        }
        if let Some(usage) = self.usage {
            write!(
                writer,
                " usage=available original_bytes={} fragments={} completed_fragments={} decoded_bytes={} work_units={} finding_records={} finding_payload_bytes={} collected_spans={} normalization_bytes={} usage_exact={}",
                usage.original_bytes(),
                usage.fragments(),
                usage.completed_fragments(),
                usage.decoded_bytes(),
                usage.work_units(),
                usage.finding_records(),
                usage.finding_payload_bytes(),
                usage.collected_spans(),
                usage.normalization_bytes(),
                usize::from(usage.is_exact())
            )?;
        } else {
            write!(writer, " usage=unavailable")?;
        }
        writeln!(
            writer,
            " issues={} scm_link_bytes={}",
            self.issues, self.scm_link_bytes
        )
    }
}

pub(crate) const fn resource_name(kind: SourceBudgetKind) -> &'static str {
    match kind {
        SourceBudgetKind::OriginalBytes => "original_bytes",
        SourceBudgetKind::Fragments => "fragments",
        SourceBudgetKind::Issues => "issues",
        SourceBudgetKind::DecodedBytes => "decoded_bytes",
        SourceBudgetKind::WorkUnits => "work_units",
        SourceBudgetKind::FindingRecords => "finding_records",
        SourceBudgetKind::FindingPayloadBytes => "finding_payload_bytes",
        SourceBudgetKind::CollectedSpans => "collected_spans",
        SourceBudgetKind::NormalizationBytes => "normalization_bytes",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILE: &str = "version=1\ntarget_bytes=17\noperation_original_bytes=100\noperation_fragments=2\noperation_issues=3\nworkers=1\nqueue_capacity=2\nfragment_decoded_bytes=4\noperation_decoded_bytes=5\nfragment_work_units=6\noperation_work_units=7\nfragment_finding_records=8\noperation_finding_records=9\nfragment_finding_payload_bytes=10\noperation_finding_payload_bytes=11\nfragment_collected_spans=12\noperation_collected_spans=13\nfragment_normalization_bytes=14\noperation_normalization_bytes=15\narchive_entries=16\narchive_member_bytes=17\narchive_total_bytes=18\narchive_spool_bytes=19\ngit_patch_bytes=20\ngit_patch_lines=21\ngit_stderr_bytes=22\ngit_blob_bytes=23\ngit_metadata_bytes=24\ngit_path_bytes=25\ngit_files=26\ngit_hunks=27\nscm_link_bytes=28\noperation_scm_link_bytes=29\n";

    #[test]
    fn explicit_policy_installs_every_engine_and_adapter_dimension() {
        let profile = CompleteProfile::read(PROFILE.as_bytes()).unwrap();
        let runner = profile.runner(None).unwrap();
        assert_eq!((runner.workers(), runner.queue_capacity()), (1, 2));
        // --jobs replaces only the worker count, also above the profile's
        // own maximum of 64; the queue and the budget stay the profile's.
        for jobs in [1, 3, 65, 200] {
            let replaced = profile.runner(NonZeroUsize::new(jobs)).unwrap();
            assert_eq!((replaced.workers(), replaced.queue_capacity()), (jobs, 2));
            assert_eq!(replaced.budget(), runner.budget());
        }
        let budget = runner.budget().unwrap();
        for (actual, expected) in [
            (budget.fragment_budget(), [4, 6, 8, 10, 12, 14]),
            (budget.aggregate_budget(), [5, 7, 9, 11, 13, 15]),
        ] {
            assert_eq!(
                [
                    actual.decoded_bytes(),
                    actual.work_units(),
                    actual.finding_records(),
                    actual.finding_payload_bytes(),
                    actual.collected_spans(),
                    actual.normalization_bytes(),
                ],
                expected.map(Some)
            );
        }
        assert_eq!(
            profile.file_options().unwrap().complete_target_bytes(),
            Some(17)
        );
        let archive = profile.archive_limits(3).unwrap();
        assert_eq!(
            [
                archive.maximum_depth(),
                archive.maximum_entries(),
                archive.maximum_member_bytes(),
                archive.maximum_total_bytes(),
                archive.maximum_spool_bytes()
            ],
            [3, 16, 17, 18, 19]
        );
        let git = profile.git_limits().unwrap();
        assert_eq!(
            [
                git.patch_bytes(),
                git.patch_lines(),
                git.stderr_bytes(),
                git.blob_bytes(),
                git.metadata_bytes(),
                git.path_bytes(),
                git.files(),
                git.hunks()
            ],
            [20, 21, 22, 23, 24, 25, 26, 27]
        );
    }

    #[test]
    fn parser_rejects_missing_duplicate_unknown_non_ascii_and_invalid_numbers() {
        for line in PROFILE.lines() {
            let missing = PROFILE.replace(&format!("{line}\n"), "");
            assert!(CompleteProfile::read(missing.as_bytes()).is_err());
        }
        for suffix in [
            "version=1\n",
            "private_value=synthetic-sensitive\n",
            "\0\n",
            "# \u{e9}\n",
        ] {
            let invalid = format!("{PROFILE}{suffix}");
            let error = CompleteProfile::read(invalid.as_bytes()).unwrap_err();
            assert!(!error.contains("synthetic-sensitive"));
        }
        for number in [
            "",
            "+1",
            "-1",
            "1_000",
            "1.0",
            "0x10",
            "18446744073709551616",
            "1 # note",
        ] {
            let invalid = PROFILE.replace("target_bytes=17", &format!("target_bytes={number}"));
            assert!(
                CompleteProfile::read(invalid.as_bytes()).is_err(),
                "{number}"
            );
        }
        assert!(
            CompleteProfile::read(PROFILE.replace("version=1", "version=2").as_bytes()).is_err()
        );
        for key in [
            "target_bytes",
            "workers",
            "queue_capacity",
            "archive_entries",
            "archive_member_bytes",
            "archive_total_bytes",
            "archive_spool_bytes",
            "git_patch_bytes",
            "git_patch_lines",
            "git_stderr_bytes",
            "git_blob_bytes",
            "git_metadata_bytes",
            "git_path_bytes",
            "git_files",
            "git_hunks",
            "scm_link_bytes",
            "operation_scm_link_bytes",
        ] {
            let invalid = PROFILE
                .lines()
                .map(|line| {
                    if line.starts_with(&format!("{key}=")) {
                        format!("{key}=0\n")
                    } else {
                        format!("{line}\n")
                    }
                })
                .collect::<String>();
            assert!(CompleteProfile::read(invalid.as_bytes()).is_err(), "{key}");
        }
        let valid = format!("# reviewed limits\r\n\n{}", PROFILE.replace('=', " = "));
        assert!(CompleteProfile::read(valid.as_bytes()).is_ok());
        let zero = PROFILE
            .replace("fragment_work_units=6", "fragment_work_units=0")
            .replace("operation_issues=3", "operation_issues=0");
        assert!(CompleteProfile::read(zero.as_bytes()).is_ok());
    }

    #[test]
    fn profile_reads_stop_at_the_inclusive_limit_plus_one() {
        struct Probe {
            input: std::io::Cursor<Vec<u8>>,
            consumed: usize,
            chunk: usize,
        }
        impl Read for Probe {
            fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
                assert!(self.consumed + output.len() <= MAX_PROFILE_BYTES + 1);
                let count = output.len().min(self.chunk);
                let read = self.input.read(&mut output[..count])?;
                self.consumed += read;
                Ok(read)
            }
        }
        for length in [
            MAX_PROFILE_BYTES - 1,
            MAX_PROFILE_BYTES,
            MAX_PROFILE_BYTES + 1,
            MAX_PROFILE_BYTES + 30,
        ] {
            for chunk in [1, 7, MAX_PROFILE_BYTES + 1] {
                let mut bytes = PROFILE.as_bytes().to_vec();
                bytes.push(b'#');
                bytes.resize(length, b' ');
                let mut probe = Probe {
                    input: std::io::Cursor::new(bytes),
                    consumed: 0,
                    chunk,
                };
                let result = CompleteProfile::read(&mut probe);
                assert_eq!(result.is_ok(), length <= MAX_PROFILE_BYTES);
                assert_eq!(probe.consumed, length.min(MAX_PROFILE_BYTES + 1));
            }
        }
    }

    #[test]
    fn read_error_does_not_parse_a_valid_prefix() {
        struct FailsAfterValid {
            read: bool,
        }
        impl Read for FailsAfterValid {
            fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
                if self.read {
                    return Err(io::Error::other("synthetic-private-value"));
                }
                self.read = true;
                output[..PROFILE.len()].copy_from_slice(PROFILE.as_bytes());
                Ok(PROFILE.len())
            }
        }
        let error = CompleteProfile::read(FailsAfterValid { read: false }).unwrap_err();
        assert_eq!(error, "could not read complete profile");
    }

    #[test]
    fn link_admission_is_inclusive_and_counts_all_retained_links() {
        let mut profile = CompleteProfile::read(PROFILE.as_bytes()).unwrap();
        profile.scm_link_bytes = 29;
        profile.operation_scm_link_bytes = 58;
        let mut status = CompletionStatus {
            reason: CompletionReason::Complete,
            ..CompletionStatus::default()
        };
        assert!(status.admit_link(&profile, 29));
        assert!(status.admit_link(&profile, 29));
        assert!(!status.admit_link(&profile, 1));
        assert_eq!(status.scm_link_bytes, 58);
        let failure = status.failure.unwrap();
        assert_eq!(
            (
                failure.scope,
                failure.limit,
                failure.consumed,
                failure.requested
            ),
            ("operation", 58, 58, 1)
        );
        profile.operation_scm_link_bytes = usize::MAX;
        assert!(!status.admit_link(&profile, 30));
        assert_eq!(status.failure.unwrap().scope, "link");
    }
    #[test]
    fn scheduling_limits_reject_extreme_values_before_runner_construction() {
        for (key, original, maximum) in [("workers", 1, 64), ("queue_capacity", 2, 1024)] {
            for (value, accepted) in [
                (maximum - 1, true),
                (maximum, true),
                (maximum + 1, false),
                (usize::MAX, false),
            ] {
                let input =
                    PROFILE.replace(&format!("{key}={original}\n"), &format!("{key}={value}\n"));
                assert_eq!(
                    CompleteProfile::read(input.as_bytes()).is_ok(),
                    accepted,
                    "{key}={value}"
                );
            }
        }
    }
}
