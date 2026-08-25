//! Cross-fragment filtering and scheduler-free result collection.
//!
//! Session policy is immutable and can be shared between threads. Callers own
//! mutable batches, choose their own scheduling strategy, and merge accepted
//! findings without the core creating threads or requiring an async runtime.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine as _;
use serde::de::{self, Deserialize, Deserializer, IgnoredAny, MapAccess, Visitor};
use thiserror::Error;

use crate::model::{ByteText, CommitMetadata, Finding, Fragment, RequiredFinding};

const GO_SCANNER_TOKEN_LIMIT: usize = 64 * 1024;

/// A normalized opaque Rustleaks fingerprint-ignore set.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IgnoreSet {
    entries: BTreeSet<ByteText>,
}

impl IgnoreSet {
    /// Parses one complete `.rustleaksignore` byte stream.
    ///
    /// The legacy `.gitleaksignore` filename uses the same format for backward
    /// compatibility.
    #[must_use]
    pub fn parse_go_compatible(bytes: &[u8]) -> IgnoreParseOutcome {
        let mut ignores = Self::default();
        let issues = ignores.extend_go_compatible(bytes);
        IgnoreParseOutcome { ignores, issues }
    }

    /// Adds entries from another complete ignore-file byte stream.
    ///
    /// Existing entries remain installed and duplicates collapse. Like the
    /// pinned Go scanner, an overlong token stops this input after retaining
    /// entries parsed before it.
    pub fn extend_go_compatible(&mut self, bytes: &[u8]) -> Vec<IgnoreIssue> {
        let mut issues = Vec::new();
        let mut offset = 0;
        while offset < bytes.len() {
            let remaining = &bytes[offset..];
            let newline = remaining.iter().position(|byte| *byte == b'\n');
            let consumed = newline.map_or(remaining.len(), |index| index + 1);
            let mut token = &remaining[..newline.unwrap_or(remaining.len())];
            if token.len() >= GO_SCANNER_TOKEN_LIMIT {
                issues.push(IgnoreIssue::TokenTooLong { offset });
                break;
            }
            if token.last() == Some(&b'\r') {
                token = &token[..token.len() - 1];
            }
            let token = trim_go_space(token);
            if !token.is_empty() && !token.starts_with(b"#") {
                let field_count = token.split(|byte| *byte == b':').count();
                match field_count {
                    3 | 4 => {}
                    fields => issues.push(IgnoreIssue::InvalidFieldCount {
                        entry: token.into(),
                        fields,
                    }),
                }
                // Normalization above needs owned storage. Rebuild directly so
                // temporary replacement buffers never escape this iteration.
                let normalized = normalize_ignore_entry(token);
                self.entries.insert(normalized.into());
            }
            offset += consumed;
        }
        issues
    }

    /// Returns whether the exact normalized fingerprint is installed.
    #[must_use]
    pub fn contains(&self, fingerprint: &[u8]) -> bool {
        self.entries.contains(fingerprint)
    }

    /// Returns the number of distinct installed fingerprints.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterates normalized keys in deterministic byte order.
    pub fn iter(&self) -> impl Iterator<Item = &ByteText> {
        self.entries.iter()
    }
}

/// Result of parsing an ignore byte stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IgnoreParseOutcome {
    /// The exact normalized membership set.
    pub ignores: IgnoreSet,
    /// Nonfatal compatibility diagnostics.
    pub issues: Vec<IgnoreIssue>,
}

/// A nonfatal condition observed while parsing an ignore byte stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IgnoreIssue {
    /// An entry had an arity other than the recognized global or commit form.
    InvalidFieldCount {
        /// The trimmed entry, retained in the ignore set unchanged.
        entry: ByteText,
        /// The number of colon-separated fields.
        fields: usize,
    },
    /// The default Go scanner token limit stopped parsing this input.
    TokenTooLong {
        /// Byte offset at which the rejected token started.
        offset: usize,
    },
}

fn normalize_ignore_entry(entry: &[u8]) -> Vec<u8> {
    let fields = entry.split(|byte| *byte == b':').collect::<Vec<_>>();
    let normalized_index = match fields.len() {
        3 => Some(0),
        4 => Some(1),
        _ => None,
    };
    let mut result = Vec::with_capacity(entry.len());
    for (index, field) in fields.iter().enumerate() {
        if index != 0 {
            result.push(b':');
        }
        if normalized_index == Some(index) {
            result.extend(
                field
                    .iter()
                    .map(|byte| if *byte == b'\\' { b'/' } else { *byte }),
            );
        } else {
            result.extend_from_slice(field);
        }
    }
    result
}

fn trim_go_space(bytes: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = bytes.len();
    while start < end {
        let (value, width) = decode_first_go_rune(&bytes[start..end]);
        if !is_go_space(value) {
            break;
        }
        start += width;
    }
    while start < end {
        let (value, width) = decode_last_go_rune(&bytes[start..end]);
        if !is_go_space(value) {
            break;
        }
        end -= width;
    }
    &bytes[start..end]
}

fn decode_first_go_rune(bytes: &[u8]) -> (u32, usize) {
    let Some(&first) = bytes.first() else {
        return (0, 0);
    };
    if first < 0x80 {
        return (u32::from(first), 1);
    }
    for width in 2..=4.min(bytes.len()) {
        if let Ok(value) = std::str::from_utf8(&bytes[..width]) {
            if value.chars().count() == 1 {
                return (u32::from(value.chars().next().unwrap_or('\u{fffd}')), width);
            }
        }
    }
    (0xfffd, 1)
}

fn decode_last_go_rune(bytes: &[u8]) -> (u32, usize) {
    let Some(&last) = bytes.last() else {
        return (0, 0);
    };
    if last < 0x80 {
        return (u32::from(last), 1);
    }
    for width in 2..=4.min(bytes.len()) {
        if let Ok(value) = std::str::from_utf8(&bytes[bytes.len() - width..]) {
            if value.chars().count() == 1 {
                return (u32::from(value.chars().next().unwrap_or('\u{fffd}')), width);
            }
        }
    }
    (0xfffd, 1)
}

const fn is_go_space(value: u32) -> bool {
    matches!(
        value,
        0x0009..=0x000d
            | 0x0020
            | 0x0085
            | 0x00a0
            | 0x1680
            | 0x2000..=0x200a
            | 0x2028
            | 0x2029
            | 0x202f
            | 0x205f
            | 0x3000
    )
}

/// A permissive report entry retained from a Go-compatible baseline.
#[derive(Clone, Default, PartialEq)]
pub struct BaselineFinding {
    rule_id: ByteText,
    description: ByteText,
    start_line: i128,
    end_line: i128,
    start_column: i128,
    end_column: i128,
    match_text: ByteText,
    secret: ByteText,
    file: ByteText,
    symlink_file: ByteText,
    commit: ByteText,
    link: ByteText,
    entropy: f32,
    author: ByteText,
    email: ByteText,
    date: ByteText,
    message: ByteText,
    tags: Vec<ByteText>,
    fingerprint: ByteText,
}

impl fmt::Debug for BaselineFinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BaselineFinding")
            .field("rule_id_len", &self.rule_id.len())
            .field("description_len", &self.description.len())
            .field("start_line", &self.start_line)
            .field("end_line", &self.end_line)
            .field("start_column", &self.start_column)
            .field("end_column", &self.end_column)
            .field("match_len", &self.match_text.len())
            .field("secret_len", &self.secret.len())
            .field("file_len", &self.file.len())
            .field("symlink_file_len", &self.symlink_file.len())
            .field("commit_len", &self.commit.len())
            .field("link_len", &self.link.len())
            .field("entropy", &self.entropy)
            .field("author_len", &self.author.len())
            .field("email_len", &self.email.len())
            .field("date_len", &self.date.len())
            .field("message_len", &self.message.len())
            .field("tag_count", &self.tags.len())
            .field("fingerprint_len", &self.fingerprint.len())
            .finish()
    }
}

impl BaselineFinding {
    fn from_finding(finding: &Finding) -> Self {
        let location = finding.location();
        Self {
            rule_id: finding.rule_id().clone(),
            description: finding.description().clone(),
            start_line: usize_to_i128(location.start_line()),
            end_line: usize_to_i128(location.end_line()),
            start_column: usize_to_i128(location.start_column()),
            end_column: usize_to_i128(location.end_column()),
            match_text: finding.match_text().clone(),
            secret: finding.secret().clone(),
            file: finding.file().clone(),
            symlink_file: finding.symlink_file().clone(),
            commit: finding.commit().clone(),
            link: finding.link().clone(),
            entropy: finding.entropy(),
            author: finding.author().clone(),
            email: finding.email().clone(),
            date: finding.date().clone(),
            message: finding.message().clone(),
            tags: finding.tags().to_vec(),
            fingerprint: finding.fingerprint().clone(),
        }
    }

    /// Returns the matched rule ID.
    #[must_use]
    pub const fn rule_id(&self) -> &ByteText {
        &self.rule_id
    }
    /// Returns the rule description.
    #[must_use]
    pub const fn description(&self) -> &ByteText {
        &self.description
    }
    /// Returns the signed baseline start line.
    #[must_use]
    pub const fn start_line(&self) -> i128 {
        self.start_line
    }
    /// Returns the signed baseline end line.
    #[must_use]
    pub const fn end_line(&self) -> i128 {
        self.end_line
    }
    /// Returns the signed baseline start column.
    #[must_use]
    pub const fn start_column(&self) -> i128 {
        self.start_column
    }
    /// Returns the signed baseline end column.
    #[must_use]
    pub const fn end_column(&self) -> i128 {
        self.end_column
    }
    /// Returns the baseline match bytes.
    #[must_use]
    pub const fn match_text(&self) -> &ByteText {
        &self.match_text
    }
    /// Returns the baseline secret bytes.
    #[must_use]
    pub const fn secret(&self) -> &ByteText {
        &self.secret
    }
    /// Returns the baseline file bytes.
    #[must_use]
    pub const fn file(&self) -> &ByteText {
        &self.file
    }
    /// Returns the ignored symlink-file bytes retained from the report.
    #[must_use]
    pub const fn symlink_file(&self) -> &ByteText {
        &self.symlink_file
    }
    /// Returns the commit bytes.
    #[must_use]
    pub const fn commit(&self) -> &ByteText {
        &self.commit
    }
    /// Returns the ignored link bytes retained from the report.
    #[must_use]
    pub const fn link(&self) -> &ByteText {
        &self.link
    }
    /// Returns the upstream-compatible `f32` entropy.
    #[must_use]
    pub const fn entropy(&self) -> f32 {
        self.entropy
    }
    /// Returns the author bytes.
    #[must_use]
    pub const fn author(&self) -> &ByteText {
        &self.author
    }
    /// Returns the email bytes.
    #[must_use]
    pub const fn email(&self) -> &ByteText {
        &self.email
    }
    /// Returns the date bytes.
    #[must_use]
    pub const fn date(&self) -> &ByteText {
        &self.date
    }
    /// Returns the message bytes.
    #[must_use]
    pub const fn message(&self) -> &ByteText {
        &self.message
    }
    /// Returns ignored tags retained in report order.
    #[must_use]
    pub fn tags(&self) -> &[ByteText] {
        &self.tags
    }
    /// Returns the ignored baseline fingerprint.
    #[must_use]
    pub const fn fingerprint(&self) -> &ByteText {
        &self.fingerprint
    }
}

/// An immutable collection loaded from a baseline report.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Baseline {
    entries: Vec<BaselineFinding>,
    was_null: bool,
}

impl Baseline {
    /// Builds a baseline from already validated findings.
    #[must_use]
    pub fn from_findings(findings: &[Finding]) -> Self {
        Self {
            entries: findings.iter().map(BaselineFinding::from_finding).collect(),
            was_null: false,
        }
    }

    /// Parses the pinned Go report JSON format from bytes.
    ///
    /// # Errors
    ///
    /// Returns [`BaselineParseError`] for malformed JSON, a non-array root, a
    /// wrong known field type, or a value outside the pinned 64-bit Go domain.
    pub fn from_go_json(bytes: &[u8]) -> Result<Self, BaselineParseError> {
        let normalized = normalize_go_json(bytes);
        let decoded = serde_json::from_str::<Option<Vec<BaselineFindingWire>>>(&normalized)
            .map_err(BaselineParseError::Json)?;
        Ok(match decoded {
            Some(entries) => Self {
                entries: entries.into_iter().map(Into::into).collect(),
                was_null: false,
            },
            None => Self {
                entries: Vec::new(),
                was_null: true,
            },
        })
    }

    /// Reads and parses a named baseline report.
    ///
    /// # Errors
    ///
    /// Returns a structured I/O or JSON error without platform-dependent
    /// presentation text.
    pub fn load_go_json(path: impl AsRef<Path>) -> Result<Self, BaselineLoadError> {
        let path = path.as_ref();
        let bytes = fs::read(path).map_err(|source| BaselineLoadError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_go_json(&bytes).map_err(|source| BaselineLoadError::Parse {
            path: path.to_path_buf(),
            source,
        })
    }

    /// Returns retained baseline entries in file order, including duplicates.
    #[must_use]
    pub fn entries(&self) -> &[BaselineFinding] {
        &self.entries
    }
    /// Returns the retained entry count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    /// Returns whether the retained list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    /// Returns whether the top-level report value was JSON `null`.
    #[must_use]
    pub const fn was_null(&self) -> bool {
        self.was_null
    }

    /// Returns whether no baseline entry equals the finding.
    #[must_use]
    pub fn is_new(&self, finding: &Finding, redaction_percent: usize) -> bool {
        self.entries
            .iter()
            .all(|entry| !baseline_equal(entry, finding, redaction_percent))
    }
}

/// A structured baseline JSON parse failure.
#[derive(Debug, Error)]
pub enum BaselineParseError {
    /// The input did not decode as the pinned report shape.
    #[error("unsupported baseline JSON: {0}")]
    Json(serde_json::Error),
}

/// A structured baseline file load failure.
#[derive(Debug, Error)]
pub enum BaselineLoadError {
    /// Reading the named file failed.
    #[error("could not read baseline {path}: {source}")]
    Io {
        /// The requested path.
        path: PathBuf,
        /// The underlying portable standard-library error.
        #[source]
        source: std::io::Error,
    },
    /// The file was read but its report shape was unsupported.
    #[error("could not parse baseline {path}: {source}")]
    Parse {
        /// The requested path.
        path: PathBuf,
        /// The structured parser error.
        #[source]
        source: BaselineParseError,
    },
}

#[allow(clippy::float_cmp)] // Pinned Go baseline equality uses exact float32 `==`.
fn baseline_equal(entry: &BaselineFinding, finding: &Finding, redact: usize) -> bool {
    let location = finding.location();
    entry.rule_id == *finding.rule_id()
        && entry.description == *finding.description()
        && entry.start_line == usize_to_i128(location.start_line())
        && entry.end_line == usize_to_i128(location.end_line())
        && entry.start_column == usize_to_i128(location.start_column())
        && entry.end_column == usize_to_i128(location.end_column())
        && (redact > 0
            || (entry.match_text == *finding.match_text() && entry.secret == *finding.secret()))
        && entry.file == *finding.file()
        && entry.commit == *finding.commit()
        && entry.author == *finding.author()
        && entry.email == *finding.email()
        && entry.date == *finding.date()
        && entry.message == *finding.message()
        && entry.entropy == finding.entropy()
}

fn usize_to_i128(value: usize) -> i128 {
    i128::try_from(value).unwrap_or(i128::MAX)
}

/// Builds the global `file:rule:start-line` fingerprint.
#[must_use]
pub fn global_fingerprint(finding: &Finding) -> ByteText {
    let mut bytes = Vec::with_capacity(finding.file().len() + finding.rule_id().len() + 22);
    bytes.extend_from_slice(finding.file().as_bytes());
    bytes.push(b':');
    bytes.extend_from_slice(finding.rule_id().as_bytes());
    bytes.push(b':');
    bytes.extend_from_slice(finding.location().start_line().to_string().as_bytes());
    bytes.into()
}

/// Builds the commit-qualified fingerprint, or the global form for no commit.
#[must_use]
pub fn qualified_fingerprint(finding: &Finding) -> ByteText {
    let global = global_fingerprint(finding);
    if finding.commit().is_empty() {
        return global;
    }
    let mut bytes = Vec::with_capacity(finding.commit().len() + global.len() + 1);
    bytes.extend_from_slice(finding.commit().as_bytes());
    bytes.push(b':');
    bytes.extend_from_slice(global.as_bytes());
    bytes.into()
}

/// Why an assigned finding was not collected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SuppressionReason {
    /// Its global fingerprint appeared in a native or legacy ignore file.
    GlobalIgnore,
    /// Its commit-qualified fingerprint appeared in a native or legacy ignore file.
    CommitIgnore,
    /// It was equal to an entry in the configured baseline.
    Baseline,
}

/// The result of assigning and filtering one finding.
#[derive(Clone, Eq, PartialEq)]
pub enum AddOutcome {
    /// The finding was retained under this assigned fingerprint.
    Accepted {
        /// The fingerprint assigned before collection.
        fingerprint: ByteText,
    },
    /// The finding was rejected under this assigned fingerprint.
    Suppressed {
        /// The fingerprint assigned before suppression.
        fingerprint: ByteText,
        /// The first matching suppression stage.
        reason: SuppressionReason,
    },
}

impl fmt::Debug for AddOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accepted { fingerprint } => formatter
                .debug_struct("Accepted")
                .field("fingerprint_len", &fingerprint.len())
                .finish(),
            Self::Suppressed {
                fingerprint,
                reason,
            } => formatter
                .debug_struct("Suppressed")
                .field("fingerprint_len", &fingerprint.len())
                .field("reason", reason)
                .finish(),
        }
    }
}

impl AddOutcome {
    /// Returns the assigned fingerprint for either disposition.
    #[must_use]
    pub const fn fingerprint(&self) -> &ByteText {
        match self {
            Self::Accepted { fingerprint } | Self::Suppressed { fingerprint, .. } => fingerprint,
        }
    }

    /// Returns the suppression reason, if any.
    #[must_use]
    pub const fn suppression_reason(&self) -> Option<SuppressionReason> {
        match self {
            Self::Accepted { .. } => None,
            Self::Suppressed { reason, .. } => Some(*reason),
        }
    }

    /// Returns whether the finding was accepted.
    #[must_use]
    pub const fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted { .. })
    }
}

#[derive(Clone, Debug, Default)]
struct PolicyData {
    ignores: IgnoreSet,
    baseline: Option<Baseline>,
    redaction_percent: usize,
}

/// Immutable filtering policy shared by owned scan batches.
#[derive(Clone, Debug, Default)]
pub struct SessionPolicy(Arc<PolicyData>);

impl SessionPolicy {
    /// Starts a policy builder.
    #[must_use]
    pub fn builder() -> SessionPolicyBuilder {
        SessionPolicyBuilder::default()
    }

    /// Assigns a fingerprint and classifies an owned finding.
    #[must_use]
    pub fn classify(&self, mut finding: Finding) -> ClassifiedFinding {
        let global = global_fingerprint(&finding);
        let qualified = qualified_fingerprint(&finding);
        finding.assign_fingerprint(qualified.clone());
        let reason = if self.0.ignores.contains(global.as_bytes()) {
            Some(SuppressionReason::GlobalIgnore)
        } else if !finding.commit().is_empty() && self.0.ignores.contains(qualified.as_bytes()) {
            Some(SuppressionReason::CommitIgnore)
        } else if self
            .0
            .baseline
            .as_ref()
            .is_some_and(|baseline| !baseline.is_new(&finding, self.0.redaction_percent))
        {
            Some(SuppressionReason::Baseline)
        } else {
            None
        };
        let outcome = match reason {
            Some(reason) => AddOutcome::Suppressed {
                fingerprint: qualified,
                reason,
            },
            None => AddOutcome::Accepted {
                fingerprint: qualified,
            },
        };
        ClassifiedFinding { finding, outcome }
    }

    /// Creates an empty owned batch using this exact policy identity.
    #[must_use]
    pub fn new_batch(&self) -> SessionBatch {
        SessionBatch {
            policy: self.clone(),
            findings: Vec::new(),
        }
    }
}

/// Builder for an immutable [`SessionPolicy`].
#[derive(Clone, Debug, Default)]
pub struct SessionPolicyBuilder {
    data: PolicyData,
}

impl SessionPolicyBuilder {
    /// Installs an immutable ignore set.
    #[must_use]
    pub fn ignores(mut self, ignores: IgnoreSet) -> Self {
        self.data.ignores = ignores;
        self
    }
    /// Installs a baseline. An empty baseline remains configured.
    #[must_use]
    pub fn baseline(mut self, baseline: Baseline) -> Self {
        self.data.baseline = Some(baseline);
        self
    }
    /// Sets the comparison redaction mode; any nonzero value omits match/secret.
    #[must_use]
    pub const fn redaction_percent(mut self, percent: usize) -> Self {
        self.data.redaction_percent = percent;
        self
    }
    /// Finishes the immutable policy.
    #[must_use]
    pub fn build(self) -> SessionPolicy {
        SessionPolicy(Arc::new(self.data))
    }
}

/// An owned finding together with its assigned session disposition.
#[derive(Clone, Debug)]
pub struct ClassifiedFinding {
    finding: Finding,
    outcome: AddOutcome,
}

impl ClassifiedFinding {
    /// Returns the assigned finding, including a fingerprint when suppressed.
    #[must_use]
    pub const fn finding(&self) -> &Finding {
        &self.finding
    }
    /// Returns the classification outcome.
    #[must_use]
    pub const fn outcome(&self) -> &AddOutcome {
        &self.outcome
    }
    /// Consumes the classification into its parts.
    #[must_use]
    pub fn into_parts(self) -> (Finding, AddOutcome) {
        (self.finding, self.outcome)
    }
}

/// A mutable, scheduler-free collection using one immutable policy.
#[derive(Clone, Debug)]
pub struct SessionBatch {
    policy: SessionPolicy,
    findings: Vec<Finding>,
}

impl SessionBatch {
    /// Assigns, filters, and conditionally retains one owned finding.
    pub fn add_finding(&mut self, finding: Finding) -> AddOutcome {
        let classified = self.policy.classify(finding);
        let (finding, outcome) = classified.into_parts();
        if outcome.is_accepted() {
            self.findings.push(finding);
        }
        outcome
    }

    /// Returns accepted findings in batch insertion order.
    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }
    /// Consumes the batch and returns its accepted findings.
    #[must_use]
    pub fn into_findings(self) -> Vec<Finding> {
        self.findings
    }
}

/// A session coordinator that owns merged findings without choosing a scheduler.
#[derive(Clone, Debug)]
pub struct ScanSession {
    policy: SessionPolicy,
    findings: Vec<Finding>,
}

impl ScanSession {
    /// Creates an empty session under an immutable policy.
    #[must_use]
    pub fn new(policy: SessionPolicy) -> Self {
        Self {
            policy,
            findings: Vec::new(),
        }
    }
    /// Returns the immutable filtering policy.
    #[must_use]
    pub const fn policy(&self) -> &SessionPolicy {
        &self.policy
    }
    /// Creates an independently mutable batch suitable for caller-owned work.
    #[must_use]
    pub fn new_batch(&self) -> SessionBatch {
        self.policy.new_batch()
    }
    /// Assigns, filters, and conditionally retains one owned finding.
    pub fn add_finding(&mut self, finding: Finding) -> AddOutcome {
        let mut batch = self.new_batch();
        let outcome = batch.add_finding(finding);
        self.findings.extend(batch.findings);
        outcome
    }
    /// Merges a batch created from this exact immutable policy.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyMismatch`] without changing the session when the batch
    /// came from another policy instance.
    pub fn merge(&mut self, batch: SessionBatch) -> Result<(), PolicyMismatch> {
        if !Arc::ptr_eq(&self.policy.0, &batch.policy.0) {
            return Err(PolicyMismatch);
        }
        self.findings.extend(batch.findings);
        Ok(())
    }
    /// Returns accepted findings in insertion/merge order.
    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }
    /// Returns an owned snapshot that cannot alias session storage.
    #[must_use]
    pub fn snapshot(&self) -> Vec<Finding> {
        self.findings.clone()
    }
    /// Consumes the session and returns accepted findings.
    #[must_use]
    pub fn into_findings(self) -> Vec<Finding> {
        self.findings
    }
}

/// A batch came from a different immutable policy identity.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("session batch was created from a different policy")]
pub struct PolicyMismatch;

/// Stably sorts findings by every retained raw field without deduplication.
pub fn sort_findings_canonical(findings: &mut [Finding]) {
    findings.sort_by(canonical_finding_cmp);
}

/// Compares every retained raw field in the versioned canonical order.
#[must_use]
pub fn canonical_finding_cmp(left: &Finding, right: &Finding) -> Ordering {
    let ll = left.location();
    let rl = right.location();
    left.rule_id()
        .cmp(right.rule_id())
        .then_with(|| left.description().cmp(right.description()))
        .then_with(|| ll.start_line().cmp(&rl.start_line()))
        .then_with(|| ll.end_line().cmp(&rl.end_line()))
        .then_with(|| ll.start_column().cmp(&rl.start_column()))
        .then_with(|| ll.end_column().cmp(&rl.end_column()))
        .then_with(|| left.line().cmp(right.line()))
        .then_with(|| left.match_text().cmp(right.match_text()))
        .then_with(|| left.secret().cmp(right.secret()))
        .then_with(|| left.file().cmp(right.file()))
        .then_with(|| left.symlink_file().cmp(right.symlink_file()))
        .then_with(|| left.commit().cmp(right.commit()))
        .then_with(|| left.link().cmp(right.link()))
        .then_with(|| left.entropy().to_bits().cmp(&right.entropy().to_bits()))
        .then_with(|| left.author().cmp(right.author()))
        .then_with(|| left.email().cmp(right.email()))
        .then_with(|| left.date().cmp(right.date()))
        .then_with(|| left.message().cmp(right.message()))
        .then_with(|| left.tags().cmp(right.tags()))
        .then_with(|| left.fingerprint().cmp(right.fingerprint()))
        .then_with(|| compare_optional_fragment(left.fragment(), right.fragment()))
        .then_with(|| compare_required_slices(left.required_findings(), right.required_findings()))
}

fn compare_optional_fragment(left: Option<&Fragment>, right: Option<&Fragment>) -> Ordering {
    match (left, right) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(left), Some(right)) => compare_fragment(left, right),
    }
}

fn compare_fragment(left: &Fragment, right: &Fragment) -> Ordering {
    left.content()
        .cmp(right.content())
        .then_with(|| left.file_path().cmp(right.file_path()))
        .then_with(|| left.symlink_file().cmp(right.symlink_file()))
        .then_with(|| left.windows_file_path().cmp(right.windows_file_path()))
        .then_with(|| left.commit().cmp(right.commit()))
        .then_with(|| left.start_line().cmp(&right.start_line()))
        .then_with(|| compare_optional_commit(left.commit_metadata(), right.commit_metadata()))
        .then_with(|| {
            left.inherited_from_finding()
                .cmp(&right.inherited_from_finding())
        })
}

fn compare_optional_commit(
    left: Option<&CommitMetadata>,
    right: Option<&CommitMetadata>,
) -> Ordering {
    match (left, right) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(left), Some(right)) => left
            .author_email()
            .cmp(right.author_email())
            .then_with(|| left.author_name().cmp(right.author_name()))
            .then_with(|| left.date().cmp(right.date()))
            .then_with(|| left.message().cmp(right.message()))
            .then_with(|| left.sha().cmp(right.sha())),
    }
}

fn compare_required_slices(left: &[RequiredFinding], right: &[RequiredFinding]) -> Ordering {
    for (left, right) in left.iter().zip(right) {
        let order = compare_required(left, right);
        if order != Ordering::Equal {
            return order;
        }
    }
    left.len().cmp(&right.len())
}

fn compare_required(left: &RequiredFinding, right: &RequiredFinding) -> Ordering {
    let ll = left.location();
    let rl = right.location();
    left.rule_id()
        .cmp(right.rule_id())
        .then_with(|| ll.start_line().cmp(&rl.start_line()))
        .then_with(|| ll.end_line().cmp(&rl.end_line()))
        .then_with(|| ll.start_column().cmp(&rl.start_column()))
        .then_with(|| ll.end_column().cmp(&rl.end_column()))
        .then_with(|| left.line().cmp(right.line()))
        .then_with(|| left.match_text().cmp(right.match_text()))
        .then_with(|| left.secret().cmp(right.secret()))
}

// The wire visitor intentionally retains signed coordinates separately from
// the validated public Finding model.
#[derive(Default)]
struct BaselineFindingWire(BaselineFinding);

impl From<BaselineFindingWire> for BaselineFinding {
    fn from(value: BaselineFindingWire) -> Self {
        value.0
    }
}

fn go_json_key_eq(key: &str, field: &str) -> bool {
    if key == field {
        return true;
    }
    let mut key_runes = key.chars();
    for field_byte in field.bytes() {
        let Some(key_rune) = key_runes.next() else {
            return false;
        };
        let folded = match key_rune {
            'A'..='Z' => key_rune.to_ascii_lowercase(),
            '\u{017f}' => 's', // LATIN SMALL LETTER LONG S
            '\u{212a}' => 'k', // KELVIN SIGN
            value => value,
        };
        if folded != char::from(field_byte.to_ascii_lowercase()) {
            return false;
        }
    }
    key_runes.next().is_none()
}

impl<'de> Deserialize<'de> for BaselineFindingWire {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(BaselineFindingVisitor)
    }
}

struct BaselineFindingVisitor;

impl<'de> Visitor<'de> for BaselineFindingVisitor {
    type Value = BaselineFindingWire;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a Gitleaks finding object or null")
    }
    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(BaselineFindingWire::default())
    }
    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(BaselineFindingWire::default())
    }
    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut value = BaselineFinding::default();
        while let Some(key) = map.next_key::<String>()? {
            macro_rules! scalar {
                ($field:ident, $type:ty) => {{
                    if let Some(next) = map.next_value::<Option<$type>>()? {
                        value.$field = next.into();
                    }
                }};
            }
            if go_json_key_eq(&key, "RuleID") {
                scalar!(rule_id, String);
            } else if go_json_key_eq(&key, "Description") {
                scalar!(description, String);
            } else if go_json_key_eq(&key, "StartLine") {
                if let Some(next) = map.next_value::<Option<i64>>()? {
                    value.start_line = i128::from(next);
                }
            } else if go_json_key_eq(&key, "EndLine") {
                if let Some(next) = map.next_value::<Option<i64>>()? {
                    value.end_line = i128::from(next);
                }
            } else if go_json_key_eq(&key, "StartColumn") {
                if let Some(next) = map.next_value::<Option<i64>>()? {
                    value.start_column = i128::from(next);
                }
            } else if go_json_key_eq(&key, "EndColumn") {
                if let Some(next) = map.next_value::<Option<i64>>()? {
                    value.end_column = i128::from(next);
                }
            } else if go_json_key_eq(&key, "Match") {
                scalar!(match_text, String);
            } else if go_json_key_eq(&key, "Secret") {
                scalar!(secret, String);
            } else if go_json_key_eq(&key, "File") {
                scalar!(file, String);
            } else if go_json_key_eq(&key, "SymlinkFile") {
                scalar!(symlink_file, String);
            } else if go_json_key_eq(&key, "Commit") {
                scalar!(commit, String);
            } else if go_json_key_eq(&key, "Link") {
                scalar!(link, String);
            } else if go_json_key_eq(&key, "Entropy") {
                if let Some(next) = map.next_value::<Option<f32>>()? {
                    if !next.is_finite() {
                        return Err(de::Error::custom("number overflows float32"));
                    }
                    value.entropy = next;
                }
            } else if go_json_key_eq(&key, "Author") {
                scalar!(author, String);
            } else if go_json_key_eq(&key, "Email") {
                scalar!(email, String);
            } else if go_json_key_eq(&key, "Date") {
                scalar!(date, String);
            } else if go_json_key_eq(&key, "Message") {
                scalar!(message, String);
            } else if go_json_key_eq(&key, "Tags") {
                if let Some(next) = map.next_value::<Option<Vec<String>>>()? {
                    value.tags = next.into_iter().map(Into::into).collect();
                } else {
                    value.tags.clear();
                }
            } else if go_json_key_eq(&key, "Fingerprint") {
                scalar!(fingerprint, String);
            } else if go_json_key_eq(&key, "Fragment") {
                let _: Option<ValidatedFragment> = map.next_value()?;
            } else {
                let _: IgnoredAny = map.next_value()?;
            }
        }
        Ok(BaselineFindingWire(value))
    }
}

struct ValidatedFragment;
impl<'de> Deserialize<'de> for ValidatedFragment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = ValidatedFragment;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a fragment object")
            }
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                while let Some(key) = map.next_key::<String>()? {
                    if go_json_key_eq(&key, "Raw")
                        || go_json_key_eq(&key, "FilePath")
                        || go_json_key_eq(&key, "SymlinkFile")
                        || go_json_key_eq(&key, "CommitSHA")
                    {
                        let _: Option<String> = map.next_value()?;
                    } else if go_json_key_eq(&key, "Bytes") {
                        if let Some(encoded) = map.next_value::<Option<String>>()? {
                            validate_go_base64(&encoded).map_err(de::Error::custom)?;
                        }
                    } else if go_json_key_eq(&key, "StartLine") {
                        let _: Option<i64> = map.next_value()?;
                    } else if go_json_key_eq(&key, "InheritedFromFinding") {
                        let _: Option<bool> = map.next_value()?;
                    } else if go_json_key_eq(&key, "CommitInfo") {
                        let _: Option<ValidatedCommitInfo> = map.next_value()?;
                    } else {
                        let _: IgnoredAny = map.next_value()?;
                    }
                }
                Ok(ValidatedFragment)
            }
        }
        deserializer.deserialize_map(V)
    }
}

fn validate_go_base64(encoded: &str) -> Result<(), base64::DecodeError> {
    use base64::alphabet::STANDARD;
    use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};

    let without_newlines = encoded
        .bytes()
        .filter(|byte| !matches!(byte, b'\r' | b'\n'))
        .collect::<Vec<_>>();
    GeneralPurpose::new(
        &STANDARD,
        GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
    )
    .decode(without_newlines)
    .map(|_| ())
}

struct ValidatedCommitInfo;
impl<'de> Deserialize<'de> for ValidatedCommitInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = ValidatedCommitInfo;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a commit-info object")
            }
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                while let Some(key) = map.next_key::<String>()? {
                    if go_json_key_eq(&key, "AuthorEmail")
                        || go_json_key_eq(&key, "AuthorName")
                        || go_json_key_eq(&key, "Date")
                        || go_json_key_eq(&key, "Message")
                        || go_json_key_eq(&key, "SHA")
                    {
                        let _: Option<String> = map.next_value()?;
                    } else if go_json_key_eq(&key, "Remote") {
                        let _: Option<ValidatedRemoteInfo> = map.next_value()?;
                    } else {
                        let _: IgnoredAny = map.next_value()?;
                    }
                }
                Ok(ValidatedCommitInfo)
            }
        }
        deserializer.deserialize_map(V)
    }
}

struct ValidatedRemoteInfo;
impl<'de> Deserialize<'de> for ValidatedRemoteInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = ValidatedRemoteInfo;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a remote-info object")
            }
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                while let Some(key) = map.next_key::<String>()? {
                    if go_json_key_eq(&key, "Platform") {
                        let _: Option<i64> = map.next_value()?;
                    } else if go_json_key_eq(&key, "Url") {
                        let _: Option<String> = map.next_value()?;
                    } else {
                        let _: IgnoredAny = map.next_value()?;
                    }
                }
                Ok(ValidatedRemoteInfo)
            }
        }
        deserializer.deserialize_map(V)
    }
}

fn normalize_go_json(bytes: &[u8]) -> String {
    let utf8 = go_utf8_lossy(bytes);
    replace_lone_surrogates(&utf8)
}

fn go_utf8_lossy(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len());
    let mut remaining = bytes;
    while !remaining.is_empty() {
        match std::str::from_utf8(remaining) {
            Ok(valid) => {
                output.push_str(valid);
                break;
            }
            Err(error) => {
                let valid = error.valid_up_to();
                if let Ok(prefix) = std::str::from_utf8(&remaining[..valid]) {
                    output.push_str(prefix);
                }
                output.push('\u{fffd}');
                remaining = &remaining[valid + 1..];
            }
        }
    }
    output
}

fn replace_lone_surrogates(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    let mut in_string = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'"' {
            in_string = !in_string;
            output.push(byte);
            index += 1;
            continue;
        }
        if in_string && byte == b'\\' && index + 1 < bytes.len() {
            if bytes[index + 1] == b'\\' {
                output.extend_from_slice(&bytes[index..index + 2]);
                index += 2;
                continue;
            }
            if bytes[index + 1] == b'u' && index + 6 <= bytes.len() {
                if let Some(code) = four_hex(&bytes[index + 2..index + 6]) {
                    if (0xd800..=0xdbff).contains(&code) {
                        let paired = index + 12 <= bytes.len()
                            && bytes[index + 6] == b'\\'
                            && bytes[index + 7] == b'u'
                            && four_hex(&bytes[index + 8..index + 12])
                                .is_some_and(|low| (0xdc00..=0xdfff).contains(&low));
                        if paired {
                            output.extend_from_slice(&bytes[index..index + 12]);
                            index += 12;
                            continue;
                        }
                        output.extend_from_slice(b"\\ufffd");
                        index += 6;
                        continue;
                    }
                    if (0xdc00..=0xdfff).contains(&code) {
                        output.extend_from_slice(b"\\ufffd");
                        index += 6;
                        continue;
                    }
                }
            }
            output.extend_from_slice(&bytes[index..index + 2]);
            index += 2;
            continue;
        }
        output.push(byte);
        index += 1;
    }
    String::from_utf8(output).unwrap_or_else(|_| input.to_owned())
}

fn four_hex(bytes: &[u8]) -> Option<u16> {
    if bytes.len() != 4 {
        return None;
    }
    bytes.iter().try_fold(0_u16, |value, byte| {
        let digit = match byte {
            b'0'..=b'9' => u16::from(*byte - b'0'),
            b'a'..=b'f' => u16::from(*byte - b'a' + 10),
            b'A'..=b'F' => u16::from(*byte - b'A' + 10),
            _ => return None,
        };
        Some((value << 4) | digit)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Location;

    fn finding() -> Finding {
        Finding::builder()
            .rule_id("rule")
            .description("description")
            .location(Location::new(7, 8, 3, 15).unwrap())
            .line("line MATCH=secret")
            .match_text("MATCH=secret")
            .secret("secret")
            .file("src/secret.txt")
            .commit("commit-a")
            .entropy(3.25)
            .author("author")
            .email("email@example.invalid")
            .date("2025-01-02")
            .message("message")
            .build()
            .unwrap()
    }

    #[test]
    fn ignore_parser_preserves_opaque_go_behavior() {
        let parsed = IgnoreSet::parse_go_compatible(
            "\u{3000}# comment\u{3000}\r\n C:\\dir\\file.txt:rule:7 \n a:b:c:d:5 \n".as_bytes(),
        );
        let entries = parsed
            .ignores
            .iter()
            .map(ByteText::as_bytes)
            .collect::<Vec<_>>();
        assert_eq!(
            entries,
            [b"C:/dir/file.txt:rule:7".as_slice(), b"a:b:c:d:5"]
        );
        assert_eq!(parsed.issues.len(), 1);
    }

    #[test]
    fn ignore_parser_stops_at_the_go_scanner_limit() {
        let before = b"before:r:1\n";
        let mut input = before.to_vec();
        input.extend(std::iter::repeat_n(b'x', 65_536));
        input.extend_from_slice(b"\nafter:r:2\n");
        let parsed = IgnoreSet::parse_go_compatible(&input);
        assert!(parsed.ignores.contains(b"before:r:1"));
        assert!(!parsed.ignores.contains(b"after:r:2"));
        assert!(matches!(
            parsed.issues.as_slice(),
            [IgnoreIssue::TokenTooLong { .. }]
        ));

        let accepted = IgnoreSet::parse_go_compatible(&vec![b'x'; 65_535]);
        assert_eq!(accepted.ignores.len(), 1);
        assert!(
            !accepted
                .issues
                .iter()
                .any(|issue| matches!(issue, IgnoreIssue::TokenTooLong { .. }))
        );
    }

    #[test]
    fn baseline_parser_matches_go_scalar_and_unicode_edges() {
        let input = b"[{\"ruleid\":\"first\",\"RULEID\":null,\"RuleID\":\"third\",\"StartLine\":-1,\"Entropy\":-0.0},{\"RuleID\":\"\xff\"},{\"RuleID\":\"\\uD800\"}]";
        let baseline = Baseline::from_go_json(input).unwrap();
        assert_eq!(baseline.len(), 3);
        assert_eq!(baseline.entries()[0].rule_id().as_bytes(), b"third");
        assert_eq!(baseline.entries()[0].start_line(), -1);
        assert_eq!(baseline.entries()[0].entropy().to_bits(), 0x8000_0000);
        assert_eq!(baseline.entries()[1].rule_id().as_bytes(), "�".as_bytes());
        assert_eq!(baseline.entries()[2].rule_id().as_bytes(), "�".as_bytes());
        assert!(Baseline::from_go_json(b"null").unwrap().was_null());
        assert_eq!(Baseline::from_go_json(b"[null]").unwrap().len(), 1);
        assert!(Baseline::from_go_json(b"{\"RuleID\":\"wrong root\"}").is_err());
        assert!(Baseline::from_go_json(b"[{\"StartLine\":\"wrong\"}]").is_err());
        assert!(Baseline::from_go_json(b"[{\"Entropy\":3.4028236e38}]").is_err());

        let long_s = char::from_u32(0x017f).unwrap();
        let kelvin = char::from_u32(0x212a).unwrap();
        let folded_json = format!(r#"[{{"De{long_s}cription":"folded","Lin{kelvin}":"kelvin"}}]"#);
        let folded = Baseline::from_go_json(folded_json.as_bytes()).unwrap();
        assert_eq!(folded.entries()[0].description().as_bytes(), b"folded");
        assert_eq!(folded.entries()[0].link().as_bytes(), b"kelvin");
    }

    #[test]
    fn baseline_uses_exact_go_float_and_redaction_equality() {
        let positive_zero = Finding::builder()
            .rule_id("rule")
            .location(Location::new(1, 1, 1, 1).unwrap())
            .match_text("old match")
            .secret("old secret")
            .entropy(0.0)
            .build()
            .unwrap();
        let negative_zero = Finding::builder()
            .rule_id("rule")
            .location(Location::new(1, 1, 1, 1).unwrap())
            .match_text("new match")
            .secret("new secret")
            .entropy(-0.0)
            .build()
            .unwrap();
        let baseline = Baseline::from_findings(std::slice::from_ref(&positive_zero));
        assert!(baseline.is_new(&negative_zero, 0));
        assert!(!baseline.is_new(&negative_zero, 1));

        let nan = Finding::builder()
            .rule_id("rule")
            .location(Location::new(1, 1, 1, 1).unwrap())
            .entropy(f32::from_bits(0x7fc0_0001))
            .build()
            .unwrap();
        let nan_baseline = Baseline::from_findings(std::slice::from_ref(&nan));
        assert!(nan_baseline.is_new(&nan, 100));
    }

    #[test]
    fn session_filters_in_upstream_order_and_preserves_duplicates() {
        let candidate = finding();
        let baseline = Baseline::from_findings(std::slice::from_ref(&candidate));
        let ignores = IgnoreSet::parse_go_compatible(b"src/secret.txt:rule:7").ignores;
        let policy = SessionPolicy::builder()
            .ignores(ignores)
            .baseline(baseline)
            .build();
        let mut session = ScanSession::new(policy);
        let outcome = session.add_finding(candidate);
        assert_eq!(
            outcome.suppression_reason(),
            Some(SuppressionReason::GlobalIgnore)
        );
        assert_eq!(
            outcome.fingerprint().as_bytes(),
            b"commit-a:src/secret.txt:rule:7"
        );
        assert!(session.findings().is_empty());

        let mut duplicates = ScanSession::new(SessionPolicy::default());
        duplicates.add_finding(finding());
        duplicates.add_finding(finding());
        assert_eq!(duplicates.findings().len(), 2);
    }

    #[test]
    fn batches_merge_only_under_the_same_policy() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SessionPolicy>();

        let policy = SessionPolicy::default();
        let mut session = ScanSession::new(policy.clone());
        let mut batch = policy.new_batch();
        batch.add_finding(finding());
        session.merge(batch).unwrap();
        assert_eq!(session.findings().len(), 1);

        let foreign = SessionPolicy::default().new_batch();
        assert_eq!(session.merge(foreign), Err(PolicyMismatch));
        assert_eq!(session.findings().len(), 1);
    }

    #[test]
    fn caller_scheduled_batches_preserve_the_exact_multiset() {
        let policy = SessionPolicy::default();
        let workers = (0..8)
            .map(|worker| {
                let policy = policy.clone();
                std::thread::spawn(move || {
                    let mut batch = policy.new_batch();
                    for index in 0..125 {
                        let value = format!("worker-{worker}-finding-{index}");
                        let finding = Finding::builder()
                            .rule_id(value.as_bytes())
                            .location(Location::new(index, index, 0, 0).unwrap())
                            .file(value.as_bytes())
                            .build()
                            .unwrap();
                        assert!(batch.add_finding(finding).is_accepted());
                    }
                    batch
                })
            })
            .collect::<Vec<_>>();
        let mut session = ScanSession::new(policy);
        for worker in workers {
            session.merge(worker.join().unwrap()).unwrap();
        }
        assert_eq!(session.findings().len(), 1_000);
        let mut snapshot = session.snapshot();
        sort_findings_canonical(&mut snapshot);
        assert_eq!(snapshot.len(), 1_000);
        assert_eq!(session.findings().len(), 1_000);
    }

    #[test]
    fn canonical_order_observes_raw_and_nested_state_without_deduplicating() {
        fn probe(
            line: &[u8],
            entropy: f32,
            tags: [&[u8]; 2],
            windows_path: &[u8],
            required_rule: &[u8],
        ) -> Finding {
            let fragment = Fragment::builder([0xff, b'r', b'a', b'w'])
                .file_path("fragment/file")
                .windows_file_path(windows_path)
                .start_line(4)
                .build();
            let required = RequiredFinding::builder()
                .rule_id(required_rule)
                .location(Location::new(2, 2, 3, 4).unwrap())
                .line("required line")
                .match_text("required match")
                .secret("required secret")
                .build()
                .unwrap();
            Finding::builder()
                .rule_id([0xff, b'r'])
                .description("description")
                .location(Location::new(1, 1, 1, 2).unwrap())
                .line(line)
                .match_text("match")
                .secret("secret")
                .file("file")
                .entropy(entropy)
                .tags(tags)
                .fingerprint("fingerprint")
                .fragment(fragment)
                .required_findings([required])
                .build()
                .unwrap()
        }

        let base = probe(b"line", 0.0, [b"a", b"b"], b"C:\\file", b"required");
        let variants = [
            probe(b"lin\xff", 0.0, [b"a", b"b"], b"C:\\file", b"required"),
            probe(b"line", -0.0, [b"a", b"b"], b"C:\\file", b"required"),
            probe(b"line", 0.0, [b"b", b"a"], b"C:\\file", b"required"),
            probe(b"line", 0.0, [b"a", b"b"], b"D:\\file", b"required"),
            probe(b"line", 0.0, [b"a", b"b"], b"C:\\file", b"required-2"),
        ];
        for variant in &variants {
            assert_ne!(canonical_finding_cmp(&base, variant), Ordering::Equal);
        }

        let mut findings = vec![base.clone(), variants[0].clone(), base.clone()];
        sort_findings_canonical(&mut findings);
        assert_eq!(findings.len(), 3);
        assert_eq!(
            findings.iter().filter(|finding| **finding == base).count(),
            2
        );
    }
}
