//! Byte-preserving values exchanged with the detection engine.
//!
//! Upstream Gitleaks stores source data in Go strings, which may contain
//! arbitrary bytes. The types in this module consequently do not require
//! UTF-8 and expose explicit UTF-8 and lossy-display conversions.

use std::borrow::{Borrow, Cow};
use std::error::Error;
use std::fmt;
use std::ops::Range;
use std::str::Utf8Error;

use serde::ser::{SerializeSeq, SerializeStruct};
use serde::{Serialize, Serializer};

/// Owned, byte-preserving text.
///
/// `ByteText` is used for source-derived values, including paths and commit
/// metadata. Use [`ByteText::as_str`] when valid UTF-8 is required, or
/// [`ByteText::to_string_lossy`] for presentation only.
#[derive(Clone, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ByteText(Vec<u8>);

impl ByteText {
    /// Creates byte text without validating or changing the bytes.
    #[must_use]
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Returns the original bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the text as UTF-8 without allocating.
    ///
    /// Invalid UTF-8 is reported rather than replaced, preserving the caller's
    /// ability to distinguish valid and invalid source data.
    ///
    /// # Errors
    ///
    /// Returns [`Utf8Error`] when the retained bytes are not valid UTF-8.
    pub fn as_str(&self) -> Result<&str, Utf8Error> {
        std::str::from_utf8(&self.0)
    }

    /// Returns a display-oriented string, replacing invalid UTF-8 sequences.
    ///
    /// This conversion does not modify the bytes retained by this value.
    #[must_use]
    pub fn to_string_lossy(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.0)
    }

    /// Returns whether the value contains no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the byte length of the value.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Consumes the value and returns its original bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl AsRef<[u8]> for ByteText {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Borrow<[u8]> for ByteText {
    fn borrow(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl From<Vec<u8>> for ByteText {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<&[u8]> for ByteText {
    fn from(value: &[u8]) -> Self {
        Self(value.to_vec())
    }
}

impl<const N: usize> From<&[u8; N]> for ByteText {
    fn from(value: &[u8; N]) -> Self {
        Self(value.to_vec())
    }
}

impl<const N: usize> From<[u8; N]> for ByteText {
    fn from(value: [u8; N]) -> Self {
        Self(value.to_vec())
    }
}

impl From<String> for ByteText {
    fn from(value: String) -> Self {
        Self(value.into_bytes())
    }
}

impl From<&str> for ByteText {
    fn from(value: &str) -> Self {
        Self(value.as_bytes().to_vec())
    }
}

impl fmt::Debug for ByteText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("ByteText").field(&self.0).finish()
    }
}

impl fmt::Display for ByteText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_string_lossy())
    }
}

impl Serialize for ByteText {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&go_utf8_lossy(self.as_bytes()))
    }
}

fn go_utf8_lossy(bytes: &[u8]) -> Cow<'_, str> {
    if let Ok(valid) = std::str::from_utf8(bytes) {
        return Cow::Borrowed(valid);
    }

    // Go's JSON encoder replaces each invalid UTF-8 byte with U+FFFD. Process
    // one offending byte at a time instead of inheriting another library's
    // grouping of malformed sequences.
    let mut output = String::with_capacity(bytes.len());
    let mut remaining = bytes;
    while !remaining.is_empty() {
        match std::str::from_utf8(remaining) {
            Ok(valid) => {
                output.push_str(valid);
                break;
            }
            Err(error) => {
                let valid_up_to = error.valid_up_to();
                // SAFETY is unnecessary: `valid_up_to` is guaranteed to end a
                // valid UTF-8 prefix, so use the checked conversion.
                if let Ok(valid) = std::str::from_utf8(&remaining[..valid_up_to]) {
                    output.push_str(valid);
                }
                output.push('\u{fffd}');
                remaining = &remaining[valid_up_to + 1..];
            }
        }
    }
    Cow::Owned(output)
}

struct ByteTextSlice<'a>(&'a [ByteText]);

impl Serialize for ByteTextSlice<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for value in self.0 {
            sequence.serialize_element(value)?;
        }
        sequence.end()
    }
}

/// A validated, half-open byte range (`start..end`).
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ByteRange {
    start: usize,
    end: usize,
}

impl ByteRange {
    /// Constructs a range.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidByteRange`] when `end` precedes `start`.
    pub const fn new(start: usize, end: usize) -> Result<Self, ModelError> {
        if end < start {
            return Err(ModelError::InvalidByteRange { start, end });
        }
        Ok(Self { start, end })
    }

    /// Constructs a range from a start and byte length.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::ByteRangeOverflow`] when the resulting end offset
    /// cannot be represented by `usize`.
    pub fn from_start_len(start: usize, len: usize) -> Result<Self, ModelError> {
        let end = start
            .checked_add(len)
            .ok_or(ModelError::ByteRangeOverflow { start, len })?;
        Ok(Self { start, end })
    }

    /// Returns the inclusive start offset.
    #[must_use]
    pub const fn start(self) -> usize {
        self.start
    }

    /// Returns the exclusive end offset.
    #[must_use]
    pub const fn end(self) -> usize {
        self.end
    }

    /// Returns the number of bytes covered by this range.
    #[must_use]
    pub const fn len(self) -> usize {
        self.end - self.start
    }

    /// Returns whether the range covers no bytes.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.start == self.end
    }

    /// Returns the equivalent standard-library range.
    #[must_use]
    pub const fn as_range(self) -> Range<usize> {
        self.start..self.end
    }
}

impl TryFrom<Range<usize>> for ByteRange {
    type Error = ModelError;

    fn try_from(value: Range<usize>) -> Result<Self, Self::Error> {
        Self::new(value.start, value.end)
    }
}

impl From<ByteRange> for Range<usize> {
    fn from(value: ByteRange) -> Self {
        value.as_range()
    }
}

/// Exact mapping of a detected finding component into the original
/// [`Fragment`] content.
///
/// A mapping is unavailable when the finding does not originate in fragment
/// content or when a transform prevents one exact contiguous source range
/// from representing the detected component. Reporting redaction does not
/// change this original source mapping. Callers must never approximate an
/// unavailable mapping when rewriting source content.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum FindingRange {
    /// No exact contiguous range is available in the original fragment.
    #[default]
    Unavailable,
    /// The detected component maps exactly to this half-open fragment range.
    Exact(ByteRange),
}

impl FindingRange {
    /// Returns the exact range, or `None` when rewriting is unavailable.
    #[must_use]
    pub const fn exact(self) -> Option<ByteRange> {
        match self {
            Self::Exact(range) => Some(range),
            Self::Unavailable => None,
        }
    }

    /// Returns whether an exact contiguous source range is available.
    #[must_use]
    pub const fn is_exact(self) -> bool {
        matches!(self, Self::Exact(_))
    }
}

/// A finding's upstream-compatible line and byte-column coordinates.
///
/// Lines and columns deliberately permit zero. Direct upstream scans start at
/// line zero, while file fragments commonly start at line one.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Location {
    start_line: usize,
    end_line: usize,
    start_column: usize,
    end_column: usize,
}

impl Location {
    pub(crate) const fn from_upstream(
        start_line: usize,
        end_line: usize,
        start_column: usize,
        end_column: usize,
    ) -> Self {
        Self {
            start_line,
            end_line,
            start_column,
            end_column,
        }
    }

    /// Creates a location after validating its ordering.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidLineRange`] when the end line precedes the
    /// start line, or [`ModelError::InvalidColumnRange`] for reversed columns
    /// on a single line.
    pub const fn new(
        start_line: usize,
        end_line: usize,
        start_column: usize,
        end_column: usize,
    ) -> Result<Self, ModelError> {
        if end_line < start_line {
            return Err(ModelError::InvalidLineRange {
                start: start_line,
                end: end_line,
            });
        }
        if start_line == end_line && end_column < start_column {
            return Err(ModelError::InvalidColumnRange {
                start: start_column,
                end: end_column,
            });
        }
        Ok(Self {
            start_line,
            end_line,
            start_column,
            end_column,
        })
    }

    /// Returns the start line.
    #[must_use]
    pub const fn start_line(self) -> usize {
        self.start_line
    }

    /// Returns the end line.
    #[must_use]
    pub const fn end_line(self) -> usize {
        self.end_line
    }

    /// Returns the start byte column.
    #[must_use]
    pub const fn start_column(self) -> usize {
        self.start_column
    }

    /// Returns the end byte column.
    #[must_use]
    pub const fn end_column(self) -> usize {
        self.end_column
    }
}

/// Git commit metadata supplied by a source adapter.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct CommitMetadata {
    sha: ByteText,
    author_name: ByteText,
    author_email: ByteText,
    date: ByteText,
    message: ByteText,
}

impl fmt::Debug for CommitMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommitMetadata")
            .field("sha_len", &self.sha.len())
            .field("author_name_len", &self.author_name.len())
            .field("author_email_len", &self.author_email.len())
            .field("date_len", &self.date.len())
            .field("message_len", &self.message.len())
            .finish()
    }
}

impl CommitMetadata {
    /// Starts a commit metadata builder.
    #[must_use]
    pub fn builder() -> CommitMetadataBuilder {
        CommitMetadataBuilder::default()
    }

    /// Returns the commit SHA.
    #[must_use]
    pub const fn sha(&self) -> &ByteText {
        &self.sha
    }

    /// Returns the author's display name.
    #[must_use]
    pub const fn author_name(&self) -> &ByteText {
        &self.author_name
    }

    /// Returns the author's email address.
    #[must_use]
    pub const fn author_email(&self) -> &ByteText {
        &self.author_email
    }

    /// Returns the upstream date text without interpreting it.
    #[must_use]
    pub const fn date(&self) -> &ByteText {
        &self.date
    }

    /// Returns the commit message.
    #[must_use]
    pub const fn message(&self) -> &ByteText {
        &self.message
    }
}

impl Serialize for CommitMetadata {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("CommitInfo", 6)?;
        state.serialize_field("AuthorEmail", &self.author_email)?;
        state.serialize_field("AuthorName", &self.author_name)?;
        state.serialize_field("Date", &self.date)?;
        state.serialize_field("Message", &self.message)?;
        state.serialize_field("Remote", &Option::<()>::None)?;
        state.serialize_field("SHA", &self.sha)?;
        state.end()
    }
}

/// Builder for [`CommitMetadata`].
#[derive(Clone, Default)]
pub struct CommitMetadataBuilder {
    metadata: CommitMetadata,
}

impl fmt::Debug for CommitMetadataBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommitMetadataBuilder")
            .field("metadata", &self.metadata)
            .finish()
    }
}

impl CommitMetadataBuilder {
    /// Sets the commit SHA.
    #[must_use]
    pub fn sha(mut self, value: impl Into<ByteText>) -> Self {
        self.metadata.sha = value.into();
        self
    }

    /// Sets the author's display name.
    #[must_use]
    pub fn author_name(mut self, value: impl Into<ByteText>) -> Self {
        self.metadata.author_name = value.into();
        self
    }

    /// Sets the author's email address.
    #[must_use]
    pub fn author_email(mut self, value: impl Into<ByteText>) -> Self {
        self.metadata.author_email = value.into();
        self
    }

    /// Sets the upstream date text.
    #[must_use]
    pub fn date(mut self, value: impl Into<ByteText>) -> Self {
        self.metadata.date = value.into();
        self
    }

    /// Sets the commit message.
    #[must_use]
    pub fn message(mut self, value: impl Into<ByteText>) -> Self {
        self.metadata.message = value.into();
        self
    }

    /// Finishes the metadata value.
    #[must_use]
    pub fn build(self) -> CommitMetadata {
        self.metadata
    }
}

/// A byte fragment and optional source metadata presented to the engine.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct Fragment {
    content: ByteText,
    file_path: ByteText,
    symlink_file: ByteText,
    windows_file_path: ByteText,
    commit: ByteText,
    start_line: usize,
    commit_metadata: Option<CommitMetadata>,
    inherited_from_finding: bool,
}

impl fmt::Debug for Fragment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Fragment")
            .field("content_len", &self.content.len())
            .field("file_path_len", &self.file_path.len())
            .field("symlink_file_len", &self.symlink_file.len())
            .field("windows_file_path_len", &self.windows_file_path.len())
            .field("commit_len", &self.commit.len())
            .field("start_line", &self.start_line)
            .field("commit_metadata", &self.commit_metadata)
            .field("inherited_from_finding", &self.inherited_from_finding)
            .finish()
    }
}

impl Fragment {
    /// Creates a fragment containing the supplied bytes and no metadata.
    #[must_use]
    pub fn new(content: impl Into<ByteText>) -> Self {
        Self {
            content: content.into(),
            ..Self::default()
        }
    }

    /// Starts a fragment builder with the supplied bytes.
    #[must_use]
    pub fn builder(content: impl Into<ByteText>) -> FragmentBuilder {
        FragmentBuilder {
            fragment: Self::new(content),
        }
    }

    /// Replaces only the three source-path views while consuming the fragment.
    ///
    /// This preserves the existing content and source metadata allocations,
    /// which lets adapters translate paths without copying caller-sized input.
    #[must_use]
    pub fn with_source_paths(
        mut self,
        file_path: ByteText,
        symlink_file: ByteText,
        windows_file_path: ByteText,
    ) -> Self {
        self.file_path = file_path;
        self.symlink_file = symlink_file;
        self.windows_file_path = windows_file_path;
        self
    }

    /// Returns the exact fragment bytes.
    #[must_use]
    pub const fn content(&self) -> &ByteText {
        &self.content
    }

    /// Returns the normalized `/`-separated path, or an empty value.
    #[must_use]
    pub const fn file_path(&self) -> &ByteText {
        &self.file_path
    }

    /// Returns the symlink path, or an empty value.
    #[must_use]
    pub const fn symlink_file(&self) -> &ByteText {
        &self.symlink_file
    }

    /// Returns the original Windows path retained for compatibility.
    #[must_use]
    pub const fn windows_file_path(&self) -> &ByteText {
        &self.windows_file_path
    }

    /// Returns the legacy commit SHA field, or an empty value.
    #[must_use]
    pub const fn commit(&self) -> &ByteText {
        &self.commit
    }

    /// Returns the line number on which this fragment starts.
    #[must_use]
    pub const fn start_line(&self) -> usize {
        self.start_line
    }

    /// Returns extended commit metadata when supplied.
    #[must_use]
    pub const fn commit_metadata(&self) -> Option<&CommitMetadata> {
        self.commit_metadata.as_ref()
    }

    /// Returns whether this fragment was created for required-rule detection.
    #[must_use]
    pub const fn inherited_from_finding(&self) -> bool {
        self.inherited_from_finding
    }
}

impl Serialize for Fragment {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Fragment", 8)?;
        state.serialize_field("Raw", &self.content)?;
        // Rust has one byte-first content representation. Report serialization
        // presents it through Go's Raw field and retains Go's nil Bytes shape.
        state.serialize_field("Bytes", &Option::<Vec<u8>>::None)?;
        state.serialize_field("FilePath", &self.file_path)?;
        state.serialize_field("SymlinkFile", &self.symlink_file)?;
        state.serialize_field("CommitSHA", &self.commit)?;
        state.serialize_field("StartLine", &self.start_line)?;
        state.serialize_field("CommitInfo", &self.commit_metadata)?;
        state.serialize_field("InheritedFromFinding", &self.inherited_from_finding)?;
        state.end()
    }
}

/// Builder for [`Fragment`].
#[derive(Clone)]
pub struct FragmentBuilder {
    fragment: Fragment,
}

impl fmt::Debug for FragmentBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FragmentBuilder")
            .field("fragment", &self.fragment)
            .finish()
    }
}

impl FragmentBuilder {
    /// Sets the normalized `/`-separated path.
    #[must_use]
    pub fn file_path(mut self, value: impl Into<ByteText>) -> Self {
        self.fragment.file_path = value.into();
        self
    }

    /// Sets the path through which a symlink was reached.
    #[must_use]
    pub fn symlink_file(mut self, value: impl Into<ByteText>) -> Self {
        self.fragment.symlink_file = value.into();
        self
    }

    /// Sets the original Windows path retained alongside the normalized path.
    #[must_use]
    pub fn windows_file_path(mut self, value: impl Into<ByteText>) -> Self {
        self.fragment.windows_file_path = value.into();
        self
    }

    /// Sets the legacy commit SHA field.
    #[must_use]
    pub fn commit(mut self, value: impl Into<ByteText>) -> Self {
        self.fragment.commit = value.into();
        self
    }

    /// Sets the fragment's starting line. Zero is valid for direct scans.
    #[must_use]
    pub const fn start_line(mut self, value: usize) -> Self {
        self.fragment.start_line = value;
        self
    }

    /// Sets extended commit metadata.
    #[must_use]
    pub fn commit_metadata(mut self, value: CommitMetadata) -> Self {
        self.fragment.commit_metadata = Some(value);
        self
    }

    /// Marks the fragment as originating from a primary finding.
    #[must_use]
    pub const fn inherited_from_finding(mut self, value: bool) -> Self {
        self.fragment.inherited_from_finding = value;
        self
    }

    /// Finishes the fragment.
    #[must_use]
    pub fn build(self) -> Fragment {
        self.fragment
    }
}

/// A required-rule match retained with a primary finding.
#[derive(Clone, PartialEq)]
pub struct RequiredFinding {
    rule_id: ByteText,
    location: Location,
    match_range: FindingRange,
    secret_range: FindingRange,
    line: ByteText,
    match_text: ByteText,
    secret: ByteText,
}

impl fmt::Debug for RequiredFinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequiredFinding")
            .field("rule_id_len", &self.rule_id.len())
            .field("location", &self.location)
            .field("match_range", &self.match_range)
            .field("secret_range", &self.secret_range)
            .field("line_len", &self.line.len())
            .field("match_len", &self.match_text.len())
            .field("secret_len", &self.secret.len())
            .finish()
    }
}

impl RequiredFinding {
    /// Starts a required-finding builder.
    #[must_use]
    pub fn builder() -> RequiredFindingBuilder {
        RequiredFindingBuilder::default()
    }

    /// Returns the matched rule ID.
    #[must_use]
    pub const fn rule_id(&self) -> &ByteText {
        &self.rule_id
    }

    /// Returns the source coordinates.
    #[must_use]
    pub const fn location(&self) -> Location {
        self.location
    }

    /// Returns the exact match mapping into the original fragment, if any.
    #[must_use]
    pub const fn match_range(&self) -> FindingRange {
        self.match_range
    }

    /// Returns the exact secret mapping into the original fragment, if any.
    #[must_use]
    pub const fn secret_range(&self) -> FindingRange {
        self.secret_range
    }

    /// Returns the source line bytes.
    #[must_use]
    pub const fn line(&self) -> &ByteText {
        &self.line
    }

    /// Returns the full matched bytes.
    #[must_use]
    pub const fn match_text(&self) -> &ByteText {
        &self.match_text
    }

    /// Returns the extracted secret bytes.
    #[must_use]
    pub const fn secret(&self) -> &ByteText {
        &self.secret
    }

    pub(crate) fn from_finding(finding: &Finding) -> Self {
        Self {
            rule_id: finding.rule_id.clone(),
            location: finding.location,
            match_range: finding.match_range,
            secret_range: finding.secret_range,
            line: finding.line.clone(),
            match_text: finding.match_text.clone(),
            secret: finding.secret.clone(),
        }
    }
}

impl Serialize for RequiredFinding {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("RequiredFinding", 7)?;
        state.serialize_field("RuleID", &self.rule_id)?;
        state.serialize_field("StartLine", &self.location.start_line)?;
        state.serialize_field("EndLine", &self.location.end_line)?;
        state.serialize_field("StartColumn", &self.location.start_column)?;
        state.serialize_field("EndColumn", &self.location.end_column)?;
        state.serialize_field("Match", &self.match_text)?;
        state.serialize_field("Secret", &self.secret)?;
        state.end()
    }
}

/// Builder for [`RequiredFinding`].
#[derive(Clone, Default)]
pub struct RequiredFindingBuilder {
    rule_id: Option<ByteText>,
    location: Option<Location>,
    match_range: FindingRange,
    secret_range: FindingRange,
    line: ByteText,
    match_text: ByteText,
    secret: ByteText,
}

impl fmt::Debug for RequiredFindingBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequiredFindingBuilder")
            .field("rule_id_len", &self.rule_id.as_ref().map(ByteText::len))
            .field("location", &self.location)
            .field("match_range", &self.match_range)
            .field("secret_range", &self.secret_range)
            .field("line_len", &self.line.len())
            .field("match_len", &self.match_text.len())
            .field("secret_len", &self.secret.len())
            .finish()
    }
}

impl RequiredFindingBuilder {
    /// Sets the matched rule ID.
    #[must_use]
    pub fn rule_id(mut self, value: impl Into<ByteText>) -> Self {
        self.rule_id = Some(value.into());
        self
    }

    /// Sets the source coordinates.
    #[must_use]
    pub const fn location(mut self, value: Location) -> Self {
        self.location = Some(value);
        self
    }

    /// Sets the match mapping into the original fragment.
    #[must_use]
    pub const fn match_range(mut self, value: FindingRange) -> Self {
        self.match_range = value;
        self
    }

    /// Sets the secret mapping into the original fragment.
    #[must_use]
    pub const fn secret_range(mut self, value: FindingRange) -> Self {
        self.secret_range = value;
        self
    }

    /// Sets the source line bytes.
    #[must_use]
    pub fn line(mut self, value: impl Into<ByteText>) -> Self {
        self.line = value.into();
        self
    }

    /// Sets the full matched bytes.
    #[must_use]
    pub fn match_text(mut self, value: impl Into<ByteText>) -> Self {
        self.match_text = value.into();
        self
    }

    /// Sets the extracted secret bytes.
    #[must_use]
    pub fn secret(mut self, value: impl Into<ByteText>) -> Self {
        self.secret = value.into();
        self
    }

    /// Validates and builds the required finding.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::MissingField`] when `rule_id` or `location` was
    /// not supplied.
    pub fn build(self) -> Result<RequiredFinding, ModelError> {
        Ok(RequiredFinding {
            rule_id: self.rule_id.ok_or(ModelError::MissingField {
                model: "RequiredFinding",
                field: "rule_id",
            })?,
            location: self.location.ok_or(ModelError::MissingField {
                model: "RequiredFinding",
                field: "location",
            })?,
            match_range: self.match_range,
            secret_range: self.secret_range,
            line: self.line,
            match_text: self.match_text,
            secret: self.secret,
        })
    }
}

/// A secret finding produced by the core engine.
///
/// Text and metadata remain byte-preserving. Entropy is stored as `f32` so
/// callers can compare [`f32::to_bits`] with upstream `math.Float32bits`.
#[derive(Clone, PartialEq)]
pub struct Finding {
    rule_id: ByteText,
    description: ByteText,
    location: Location,
    match_range: FindingRange,
    secret_range: FindingRange,
    line: ByteText,
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
    fragment: Option<Fragment>,
    required_findings: Vec<RequiredFinding>,
}

impl fmt::Debug for Finding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Finding")
            .field("rule_id_len", &self.rule_id.len())
            .field("description_len", &self.description.len())
            .field("location", &self.location)
            .field("match_range", &self.match_range)
            .field("secret_range", &self.secret_range)
            .field("line_len", &self.line.len())
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
            .field("has_fragment", &self.fragment.is_some())
            .field("required_finding_count", &self.required_findings.len())
            .finish()
    }
}

impl Finding {
    /// Starts a finding builder.
    #[must_use]
    pub fn builder() -> FindingBuilder {
        FindingBuilder::default()
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

    /// Returns the source coordinates.
    #[must_use]
    pub const fn location(&self) -> Location {
        self.location
    }

    /// Returns the exact match mapping into the original fragment, if any.
    #[must_use]
    pub const fn match_range(&self) -> FindingRange {
        self.match_range
    }

    /// Returns the exact secret mapping into the original fragment, if any.
    #[must_use]
    pub const fn secret_range(&self) -> FindingRange {
        self.secret_range
    }

    /// Returns the source line bytes.
    #[must_use]
    pub const fn line(&self) -> &ByteText {
        &self.line
    }

    /// Returns the full matched bytes.
    #[must_use]
    pub const fn match_text(&self) -> &ByteText {
        &self.match_text
    }

    /// Returns the extracted secret bytes.
    #[must_use]
    pub const fn secret(&self) -> &ByteText {
        &self.secret
    }

    /// Returns the normalized file path.
    #[must_use]
    pub const fn file(&self) -> &ByteText {
        &self.file
    }

    /// Returns the symlink path.
    #[must_use]
    pub const fn symlink_file(&self) -> &ByteText {
        &self.symlink_file
    }

    /// Returns the commit SHA.
    #[must_use]
    pub const fn commit(&self) -> &ByteText {
        &self.commit
    }

    /// Returns the source-control link.
    #[must_use]
    pub const fn link(&self) -> &ByteText {
        &self.link
    }

    /// Returns a copy carrying a source-control link without exposing mutable
    /// finding internals to orchestration layers.
    #[must_use]
    pub fn with_link(mut self, value: impl Into<ByteText>) -> Self {
        self.link = value.into();
        self
    }

    /// Returns the upstream-compatible entropy value.
    #[must_use]
    pub const fn entropy(&self) -> f32 {
        self.entropy
    }

    /// Returns the commit author's display name.
    #[must_use]
    pub const fn author(&self) -> &ByteText {
        &self.author
    }

    /// Returns the commit author's email address.
    #[must_use]
    pub const fn email(&self) -> &ByteText {
        &self.email
    }

    /// Returns the commit date text.
    #[must_use]
    pub const fn date(&self) -> &ByteText {
        &self.date
    }

    /// Returns the commit message.
    #[must_use]
    pub const fn message(&self) -> &ByteText {
        &self.message
    }

    /// Returns tags in insertion order, including duplicates.
    #[must_use]
    pub fn tags(&self) -> &[ByteText] {
        &self.tags
    }

    /// Returns the session-assigned fingerprint.
    #[must_use]
    pub const fn fingerprint(&self) -> &ByteText {
        &self.fingerprint
    }

    pub(crate) fn assign_fingerprint(&mut self, fingerprint: ByteText) {
        self.fingerprint = fingerprint;
    }

    /// Returns the originating fragment when retained.
    #[must_use]
    pub const fn fragment(&self) -> Option<&Fragment> {
        self.fragment.as_ref()
    }

    /// Returns required findings in insertion order, including duplicates.
    #[must_use]
    pub fn required_findings(&self) -> &[RequiredFinding] {
        &self.required_findings
    }

    /// Appends required findings without sorting or deduplicating them.
    pub fn add_required_findings(&mut self, findings: impl IntoIterator<Item = RequiredFinding>) {
        self.required_findings.extend(findings);
    }

    /// Returns a copy with its primary secret masked using Go's byte-oriented
    /// round-to-even redaction behavior.
    ///
    /// Values at or above 100 replace the secret with `REDACTED`. Required
    /// findings are intentionally left unchanged, matching the upstream
    /// reporting boundary.
    #[must_use]
    pub fn redacted(mut self, percent: usize) -> Self {
        let replacement = if percent >= 100 {
            b"REDACTED".to_vec()
        } else {
            mask_secret(self.secret.as_bytes(), percent)
        };
        self.line = replace_all_bytes(self.line.as_bytes(), self.secret.as_bytes(), &replacement);
        self.match_text = replace_all_bytes(
            self.match_text.as_bytes(),
            self.secret.as_bytes(),
            &replacement,
        );
        self.secret = replacement.into();
        self
    }

    /// Removes every detected secret byte sequence from retained finding data.
    ///
    /// This transform recursively handles required findings and drops the
    /// optional originating fragment. It preserves coordinates, exact source
    /// mappings, entropy, and collection structure, but it does not establish
    /// that other source-derived metadata is safe to disclose. Use a
    /// caller-owned projection when only approved metadata may cross a trust
    /// boundary.
    #[must_use]
    pub fn without_detected_secrets(mut self) -> Self {
        let mut secrets = self
            .required_findings
            .iter()
            .map(|finding| finding.secret.as_bytes().to_vec())
            .chain(std::iter::once(self.secret.as_bytes().to_vec()))
            .filter(|secret| !secret.is_empty())
            .collect::<Vec<_>>();
        secrets.sort_by(|left, right| right.len().cmp(&left.len()).then_with(|| left.cmp(right)));
        secrets.dedup();

        for value in [
            &mut self.rule_id,
            &mut self.description,
            &mut self.line,
            &mut self.match_text,
            &mut self.secret,
            &mut self.file,
            &mut self.symlink_file,
            &mut self.commit,
            &mut self.link,
            &mut self.author,
            &mut self.email,
            &mut self.date,
            &mut self.message,
            &mut self.fingerprint,
        ] {
            remove_detected_secrets(value, &secrets);
        }
        for tag in &mut self.tags {
            remove_detected_secrets(tag, &secrets);
        }
        for finding in &mut self.required_findings {
            finding.remove_detected_secrets(&secrets);
        }
        self.secret = ByteText::default();
        self.fragment = None;
        self
    }
}

impl RequiredFinding {
    fn remove_detected_secrets(&mut self, secrets: &[Vec<u8>]) {
        for value in [
            &mut self.rule_id,
            &mut self.line,
            &mut self.match_text,
            &mut self.secret,
        ] {
            remove_detected_secrets(value, secrets);
        }
        self.secret = ByteText::default();
    }
}

fn remove_detected_secrets(value: &mut ByteText, secrets: &[Vec<u8>]) {
    for secret in secrets {
        *value = replace_all_bytes(value.as_bytes(), secret, b"");
    }
}

fn mask_secret(secret: &[u8], percent: usize) -> Vec<u8> {
    if secret.is_empty() {
        return Vec::new();
    }
    let retained = go_redaction_retained_len(secret.len(), percent.min(100));
    let mut masked = secret[..retained].to_vec();
    masked.extend_from_slice(b"...");
    masked
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]
fn go_redaction_retained_len(byte_len: usize, percent: usize) -> usize {
    // The casts and binary64 arithmetic are intentional: upstream converts
    // the byte length and percentage to float64 before math.RoundToEven.
    ((byte_len as f64) * f64::from(u32::try_from(100 - percent).unwrap_or(0)) / 100.0)
        .round_ties_even() as usize
}

fn replace_all_bytes(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> ByteText {
    if needle.is_empty() {
        if replacement.is_empty() {
            return haystack.into();
        }
        let mut output = Vec::with_capacity(
            haystack.len().saturating_add(
                replacement
                    .len()
                    .saturating_mul(haystack.len().saturating_add(1)),
            ),
        );
        output.extend_from_slice(replacement);
        let mut offset = 0;
        while offset < haystack.len() {
            let width = next_go_utf8_rune_width(&haystack[offset..]);
            output.extend_from_slice(&haystack[offset..offset + width]);
            output.extend_from_slice(replacement);
            offset += width;
        }
        return output.into();
    }
    let mut output = Vec::with_capacity(haystack.len());
    let mut offset = 0;
    while let Some(relative) = haystack[offset..]
        .windows(needle.len())
        .position(|window| window == needle)
    {
        let start = offset + relative;
        output.extend_from_slice(&haystack[offset..start]);
        output.extend_from_slice(replacement);
        offset = start + needle.len();
    }
    output.extend_from_slice(&haystack[offset..]);
    output.into()
}

fn next_go_utf8_rune_width(bytes: &[u8]) -> usize {
    let Some(&first) = bytes.first() else {
        return 0;
    };
    let width = match first {
        0x00..=0x7f => 1,
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => return 1,
    };
    if bytes.len() >= width && std::str::from_utf8(&bytes[..width]).is_ok() {
        width
    } else {
        1
    }
}

#[cfg(test)]
mod redaction_tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::path::PathBuf;

    use base64::Engine as _;
    use serde_json::Value;

    use super::mask_secret;

    #[test]
    fn private_mask_helper_matches_the_pinned_assertions() {
        for (secret, percent, expected) in [
            (b"secret".as_slice(), 75, b"se...".as_slice()),
            (b"secret".as_slice(), 90, b"s...".as_slice()),
            (b"secret".as_slice(), 10, b"secre...".as_slice()),
            (b"secret".as_slice(), 1_000, b"...".as_slice()),
            (b"".as_slice(), 75, b"".as_slice()),
        ] {
            assert_eq!(mask_secret(secret, percent), expected);
        }
    }

    #[test]
    fn private_mask_helper_replays_every_frozen_oracle_row() {
        let corpus =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../compat/composite-corpus");
        let outcomes = json_lines(&corpus.join("outcomes-v1.jsonl"))
            .into_iter()
            .map(|value| (string(&value, "id").to_owned(), value))
            .collect::<BTreeMap<_, _>>();
        let mut replayed = BTreeSet::new();

        for request in json_lines(&corpus.join("requests-v1.jsonl")) {
            if string(&request, "operation") != "mask_secret" {
                continue;
            }
            let id = string(&request, "id");
            let response = outcomes.get(id).unwrap();
            let secret = decode(string(&request["redaction"], "secret_base64"));
            let percent = usize::try_from(request["redact_percent"].as_u64().unwrap()).unwrap();
            let expected = decode(string(response, "mask_secret_base64"));
            assert_eq!(mask_secret(&secret, percent), expected, "{id}");
            replayed.insert(id.to_owned());
        }

        assert_eq!(
            replayed,
            BTreeSet::from([
                "upstream-tm-0246-high-masking".to_owned(),
                "upstream-tm-0247-invalid-masking".to_owned(),
                "upstream-tm-0248-low-masking".to_owned(),
                "upstream-tm-0249-normal-masking".to_owned(),
            ])
        );
    }

    fn json_lines(path: &std::path::Path) -> Vec<Value> {
        fs::read_to_string(path)
            .unwrap()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn string<'a>(value: &'a Value, key: &str) -> &'a str {
        value[key].as_str().unwrap()
    }

    fn decode(encoded: &str) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap()
    }
}

impl Serialize for Finding {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let field_count =
            18 + usize::from(!self.link.is_empty()) + usize::from(self.fragment.is_some());
        let mut state = serializer.serialize_struct("Finding", field_count)?;
        state.serialize_field("RuleID", &self.rule_id)?;
        state.serialize_field("Description", &self.description)?;
        state.serialize_field("StartLine", &self.location.start_line)?;
        state.serialize_field("EndLine", &self.location.end_line)?;
        state.serialize_field("StartColumn", &self.location.start_column)?;
        state.serialize_field("EndColumn", &self.location.end_column)?;
        state.serialize_field("Match", &self.match_text)?;
        state.serialize_field("Secret", &self.secret)?;
        state.serialize_field("File", &self.file)?;
        state.serialize_field("SymlinkFile", &self.symlink_file)?;
        state.serialize_field("Commit", &self.commit)?;
        if !self.link.is_empty() {
            state.serialize_field("Link", &self.link)?;
        }
        state.serialize_field("Entropy", &self.entropy)?;
        state.serialize_field("Author", &self.author)?;
        state.serialize_field("Email", &self.email)?;
        state.serialize_field("Date", &self.date)?;
        state.serialize_field("Message", &self.message)?;
        state.serialize_field("Tags", &ByteTextSlice(&self.tags))?;
        state.serialize_field("Fingerprint", &self.fingerprint)?;
        if let Some(fragment) = &self.fragment {
            state.serialize_field("Fragment", fragment)?;
        }
        state.end()
    }
}

/// Builder for [`Finding`].
#[derive(Clone, Default)]
pub struct FindingBuilder {
    rule_id: Option<ByteText>,
    description: ByteText,
    location: Option<Location>,
    match_range: FindingRange,
    secret_range: FindingRange,
    line: ByteText,
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
    fragment: Option<Fragment>,
    required_findings: Vec<RequiredFinding>,
}

impl fmt::Debug for FindingBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FindingBuilder")
            .field("rule_id_len", &self.rule_id.as_ref().map(ByteText::len))
            .field("description_len", &self.description.len())
            .field("location", &self.location)
            .field("match_range", &self.match_range)
            .field("secret_range", &self.secret_range)
            .field("line_len", &self.line.len())
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
            .field("has_fragment", &self.fragment.is_some())
            .field("required_finding_count", &self.required_findings.len())
            .finish()
    }
}

impl FindingBuilder {
    /// Sets the matched rule ID.
    #[must_use]
    pub fn rule_id(mut self, value: impl Into<ByteText>) -> Self {
        self.rule_id = Some(value.into());
        self
    }

    /// Sets the rule description.
    #[must_use]
    pub fn description(mut self, value: impl Into<ByteText>) -> Self {
        self.description = value.into();
        self
    }

    /// Sets the source coordinates.
    #[must_use]
    pub const fn location(mut self, value: Location) -> Self {
        self.location = Some(value);
        self
    }

    /// Sets the match mapping into the original fragment.
    #[must_use]
    pub const fn match_range(mut self, value: FindingRange) -> Self {
        self.match_range = value;
        self
    }

    /// Sets the secret mapping into the original fragment.
    #[must_use]
    pub const fn secret_range(mut self, value: FindingRange) -> Self {
        self.secret_range = value;
        self
    }

    /// Sets the source line bytes.
    #[must_use]
    pub fn line(mut self, value: impl Into<ByteText>) -> Self {
        self.line = value.into();
        self
    }

    /// Sets the full matched bytes.
    #[must_use]
    pub fn match_text(mut self, value: impl Into<ByteText>) -> Self {
        self.match_text = value.into();
        self
    }

    /// Sets the extracted secret bytes.
    #[must_use]
    pub fn secret(mut self, value: impl Into<ByteText>) -> Self {
        self.secret = value.into();
        self
    }

    /// Sets the normalized file path.
    #[must_use]
    pub fn file(mut self, value: impl Into<ByteText>) -> Self {
        self.file = value.into();
        self
    }

    /// Sets the symlink path.
    #[must_use]
    pub fn symlink_file(mut self, value: impl Into<ByteText>) -> Self {
        self.symlink_file = value.into();
        self
    }

    /// Sets the commit SHA.
    #[must_use]
    pub fn commit(mut self, value: impl Into<ByteText>) -> Self {
        self.commit = value.into();
        self
    }

    /// Sets the source-control link.
    #[must_use]
    pub fn link(mut self, value: impl Into<ByteText>) -> Self {
        self.link = value.into();
        self
    }

    /// Sets the `f32` entropy value.
    #[must_use]
    pub const fn entropy(mut self, value: f32) -> Self {
        self.entropy = value;
        self
    }

    /// Sets the commit author's display name.
    #[must_use]
    pub fn author(mut self, value: impl Into<ByteText>) -> Self {
        self.author = value.into();
        self
    }

    /// Sets the commit author's email address.
    #[must_use]
    pub fn email(mut self, value: impl Into<ByteText>) -> Self {
        self.email = value.into();
        self
    }

    /// Sets the commit date text.
    #[must_use]
    pub fn date(mut self, value: impl Into<ByteText>) -> Self {
        self.date = value.into();
        self
    }

    /// Sets the commit message.
    #[must_use]
    pub fn message(mut self, value: impl Into<ByteText>) -> Self {
        self.message = value.into();
        self
    }

    /// Replaces the ordered tags, preserving duplicates.
    #[must_use]
    pub fn tags(mut self, values: impl IntoIterator<Item = impl Into<ByteText>>) -> Self {
        self.tags = values.into_iter().map(Into::into).collect();
        self
    }

    /// Sets the session-assigned fingerprint.
    #[must_use]
    pub fn fingerprint(mut self, value: impl Into<ByteText>) -> Self {
        self.fingerprint = value.into();
        self
    }

    /// Retains the originating fragment.
    #[must_use]
    pub fn fragment(mut self, value: Fragment) -> Self {
        self.fragment = Some(value);
        self
    }

    /// Replaces the ordered required findings, preserving duplicates.
    #[must_use]
    pub fn required_findings(mut self, values: impl IntoIterator<Item = RequiredFinding>) -> Self {
        self.required_findings = values.into_iter().collect();
        self
    }

    /// Validates and builds the finding.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::MissingField`] when `rule_id` or `location` was
    /// not supplied.
    pub fn build(self) -> Result<Finding, ModelError> {
        Ok(Finding {
            rule_id: self.rule_id.ok_or(ModelError::MissingField {
                model: "Finding",
                field: "rule_id",
            })?,
            description: self.description,
            location: self.location.ok_or(ModelError::MissingField {
                model: "Finding",
                field: "location",
            })?,
            match_range: self.match_range,
            secret_range: self.secret_range,
            line: self.line,
            match_text: self.match_text,
            secret: self.secret,
            file: self.file,
            symlink_file: self.symlink_file,
            commit: self.commit,
            link: self.link,
            entropy: self.entropy,
            author: self.author,
            email: self.email,
            date: self.date,
            message: self.message,
            tags: self.tags,
            fingerprint: self.fingerprint,
            fragment: self.fragment,
            required_findings: self.required_findings,
        })
    }
}

/// Per-fragment options that alter core detection behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScanOptions {
    max_decode_depth: usize,
    max_target_bytes: Option<usize>,
    redaction_percent: usize,
    honor_gitleaks_allow: bool,
}

impl ScanOptions {
    /// Starts a scan-options builder.
    #[must_use]
    pub fn builder() -> ScanOptionsBuilder {
        ScanOptionsBuilder::default()
    }

    /// Returns the maximum number of recursive decode passes.
    ///
    /// This compatibility option is not an aggregate allocation limit. A
    /// controlled scan can additionally cap the cumulative successful decoded
    /// pass bytes with [`crate::ScanBudget::max_decoded_bytes`].
    #[must_use]
    pub const fn max_decode_depth(self) -> usize {
        self.max_decode_depth
    }

    /// Returns the inclusive, exact per-rule content-regexp input size, or
    /// `None`.
    ///
    /// Upstream's integer-megabyte option truncates before comparison. A
    /// compatibility adapter for an upstream value `M > 0` must therefore use
    /// `(M + 1) * 1_000_000 - 1`, with checked or saturating arithmetic.
    /// Keyword and path gates run first, and path-only rules bypass this value;
    /// it is not a fragment allocation or total-work limit.
    #[must_use]
    pub const fn max_target_bytes(self) -> Option<usize> {
        self.max_target_bytes
    }

    /// Returns the percentage of each secret to redact.
    #[must_use]
    pub const fn redaction_percent(self) -> usize {
        self.redaction_percent
    }

    /// Returns whether source lines containing a supported allow marker are honored.
    ///
    /// The native marker is `rustleaks:allow`. The legacy `gitleaks:allow`
    /// spelling is also recognized for backward compatibility.
    #[must_use]
    pub const fn honor_allow_markers(self) -> bool {
        self.honor_gitleaks_allow
    }

    /// Returns whether backward-compatible `gitleaks:allow` lines are honored.
    ///
    /// This is an upstream-compatible alias for [`Self::honor_allow_markers`].
    #[must_use]
    pub const fn honor_gitleaks_allow(self) -> bool {
        self.honor_gitleaks_allow
    }
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            // NewDetector scans only the raw fragment until the CLI supplies 5.
            max_decode_depth: 0,
            max_target_bytes: None,
            redaction_percent: 0,
            honor_gitleaks_allow: true,
        }
    }
}

/// Builder for [`ScanOptions`].
#[derive(Clone, Copy, Debug, Default)]
pub struct ScanOptionsBuilder {
    options: ScanOptions,
}

impl ScanOptionsBuilder {
    /// Sets the maximum number of recursive decode passes.
    #[must_use]
    pub const fn max_decode_depth(mut self, value: usize) -> Self {
        self.options.max_decode_depth = value;
        self
    }

    /// Sets the inclusive, exact maximum input size in bytes.
    #[must_use]
    pub const fn max_target_bytes(mut self, value: Option<usize>) -> Self {
        self.options.max_target_bytes = value;
        self
    }

    /// Sets the requested redaction percentage.
    ///
    /// Values at or above 100 are retained here and mean full redaction at the
    /// reporting boundary, matching upstream's accepted `uint` option domain.
    #[must_use]
    pub const fn redaction_percent(mut self, value: usize) -> Self {
        self.options.redaction_percent = value;
        self
    }

    /// Selects whether source lines containing supported allow markers are honored.
    ///
    /// This controls both `rustleaks:allow` and the backward-compatible
    /// `gitleaks:allow` spelling.
    #[must_use]
    pub const fn honor_allow_markers(mut self, value: bool) -> Self {
        self.options.honor_gitleaks_allow = value;
        self
    }

    /// Selects whether backward-compatible `gitleaks:allow` lines are honored.
    ///
    /// This is an upstream-compatible alias for [`Self::honor_allow_markers`].
    #[must_use]
    pub const fn honor_gitleaks_allow(mut self, value: bool) -> Self {
        self.options.honor_gitleaks_allow = value;
        self
    }

    /// Builds the options.
    #[must_use]
    pub const fn build(self) -> ScanOptions {
        self.options
    }
}

/// Structured errors produced while constructing core model values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ModelError {
    /// A byte range's end precedes its start.
    InvalidByteRange {
        /// Inclusive start offset.
        start: usize,
        /// Exclusive end offset.
        end: usize,
    },
    /// Adding a range's start and length overflowed `usize`.
    ByteRangeOverflow {
        /// Inclusive start offset.
        start: usize,
        /// Requested byte length.
        len: usize,
    },
    /// A location's end line precedes its start line.
    InvalidLineRange {
        /// Start line.
        start: usize,
        /// End line.
        end: usize,
    },
    /// A single-line location's end column precedes its start column.
    InvalidColumnRange {
        /// Start byte column.
        start: usize,
        /// End byte column.
        end: usize,
    },
    /// A required builder field was not supplied.
    MissingField {
        /// Model being constructed.
        model: &'static str,
        /// Missing field name.
        field: &'static str,
    },
}

impl fmt::Display for ModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::InvalidByteRange { start, end } => {
                write!(formatter, "byte range end {end} precedes start {start}")
            }
            Self::ByteRangeOverflow { start, len } => {
                write!(
                    formatter,
                    "byte range start {start} plus length {len} overflows"
                )
            }
            Self::InvalidLineRange { start, end } => {
                write!(
                    formatter,
                    "location end line {end} precedes start line {start}"
                )
            }
            Self::InvalidColumnRange { start, end } => write!(
                formatter,
                "location end column {end} precedes start column {start}"
            ),
            Self::MissingField { model, field } => {
                write!(
                    formatter,
                    "{model} builder is missing required field `{field}`"
                )
            }
        }
    }
}

impl Error for ModelError {}
