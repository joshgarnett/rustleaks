use std::fmt;

use rustleaks_core::model::CommitMetadata;

use super::GitLimits;
use super::process::STDOUT_CHUNK_BYTES;
use super::text::{
    git_date_to_rfc3339, split_inclusive_lines, trim_line, trim_unicode_space,
    trim_unicode_space_end, trim_unicode_space_start,
};
use crate::{Cancellation, SourceError, SourceStage};

#[derive(Clone, Eq, PartialEq)]
pub(super) struct ParsedFile {
    pub(super) path: Vec<u8>,
    pub(super) commit: Vec<u8>,
    pub(super) metadata: Option<CommitMetadata>,
    pub(super) deleted: bool,
    pub(super) binary: bool,
    pub(super) hunks: Vec<ParsedHunk>,
    /// Count of `commit ` lines before this file, for per-commit checks.
    #[cfg(any(test, feature = "fuzzing"))]
    pub(super) commit_index: usize,
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct ParsedHunk {
    pub(super) new_position: usize,
    pub(super) added: Vec<u8>,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum PatchError {
    Cancelled,
    Limit(String),
    Invalid(String),
}

pub(super) type PatchResult<T> = Result<T, PatchError>;

pub(super) fn poll_patch_cancellation(cancellation: &dyn Cancellation) -> PatchResult<()> {
    if cancellation.is_cancelled() {
        Err(PatchError::Cancelled)
    } else {
        Ok(())
    }
}

pub(super) fn patch_allocation(context: &str, error: impl fmt::Display) -> PatchError {
    PatchError::Limit(format!("could not allocate {context}: {error}"))
}

pub(super) fn copy_limited(value: &[u8], limit: usize, context: &str) -> PatchResult<Vec<u8>> {
    if value.len() > limit {
        return Err(PatchError::Limit(format!(
            "{context} exceeds the configured {limit}-byte ceiling"
        )));
    }
    let mut output = Vec::new();
    reserve_input(&mut output, value.len(), context)?;
    output.extend_from_slice(value);
    Ok(output)
}

fn push_limited(
    output: &mut Vec<u8>,
    value: &[u8],
    limit: usize,
    context: &str,
) -> PatchResult<()> {
    let required = output
        .len()
        .checked_add(value.len())
        .ok_or_else(|| PatchError::Limit(format!("{context} size overflowed usize")))?;
    if required > limit {
        return Err(PatchError::Limit(format!(
            "{context} exceeds the configured {limit}-byte ceiling"
        )));
    }
    reserve_input(output, value.len(), context)?;
    output.extend_from_slice(value);
    Ok(())
}

pub(super) fn reserve_input(
    output: &mut Vec<u8>,
    additional: usize,
    context: &str,
) -> PatchResult<()> {
    output
        .try_reserve_exact(additional)
        .map_err(|error| patch_allocation(context, error))
}

pub(super) fn fallible_clone_metadata(
    metadata: &CommitMetadata,
    limit: usize,
) -> PatchResult<CommitMetadata> {
    let sha = copy_limited(metadata.sha().as_bytes(), limit, "Git metadata SHA")?;
    let author_name = copy_limited(metadata.author_name().as_bytes(), limit, "Git author name")?;
    let author_email = copy_limited(
        metadata.author_email().as_bytes(),
        limit,
        "Git author email",
    )?;
    let date = copy_limited(metadata.date().as_bytes(), limit, "Git commit date")?;
    let message = copy_limited(metadata.message().as_bytes(), limit, "Git commit message")?;
    let total = sha
        .len()
        .checked_add(author_name.len())
        .and_then(|size| size.checked_add(author_email.len()))
        .and_then(|size| size.checked_add(date.len()))
        .and_then(|size| size.checked_add(message.len()))
        .ok_or_else(|| PatchError::Limit("Git metadata size overflowed usize".to_owned()))?;
    if total > limit {
        return Err(PatchError::Limit(format!(
            "Git commit metadata exceeds the configured {limit}-byte ceiling"
        )));
    }
    Ok(CommitMetadata::builder()
        .sha(sha)
        .author_name(author_name)
        .author_email(author_email)
        .date(date)
        .message(message)
        .build())
}

fn zero_commit_metadata() -> CommitMetadata {
    CommitMetadata::builder()
        .date(b"0001-01-01T00:00:00Z".as_slice())
        .build()
}

/// How a line of Git output relates to parser units.
#[derive(Clone, Copy, Eq, PartialEq)]
enum LineStart {
    /// A `commit ` line starts a commit and a unit.
    Commit,
    /// A `diff --git ` line starts a file record and a unit.
    Diff,
    /// Any other line continues the current unit.
    Other,
    /// An incomplete line that could still become a unit start.
    Undecided,
}

fn classify_line(line: &[u8], complete: bool) -> LineStart {
    const COMMIT: &[u8] = b"commit ";
    const DIFF: &[u8] = b"diff --git ";
    if line.starts_with(COMMIT) {
        LineStart::Commit
    } else if line.starts_with(DIFF) {
        LineStart::Diff
    } else if !complete && (COMMIT.starts_with(line) || DIFF.starts_with(line)) {
        LineStart::Undecided
    } else {
        LineStart::Other
    }
}

/// Incremental Git patch parser.
///
/// Output is split into units at every line that starts with `commit ` or
/// `diff --git `. The whole-output parser treats each such line as the start
/// of a commit or file record, or rejects it inside an incomplete hunk, so
/// parsing each unit with the commit state carried forward gives the same
/// files, in the same order, as parsing all output at once. A unit is parsed
/// only when the next unit starts or the output ends, so the result does not
/// depend on how the output was divided into chunks.
///
/// Patch bytes, patch lines, files and hunks are counted per commit, from one
/// `commit ` line to the next. Output before the first `commit ` line, such as
/// a `git diff`, counts as one commit.
pub(super) struct PatchStream {
    limits: GitLimits,
    pub(super) buffer: Vec<u8>,
    /// Start of the unit that is being collected.
    unit_start: usize,
    /// Start of the first line not yet assigned to a unit.
    scan: usize,
    /// Where the next newline search starts, at or after `scan`.
    search: usize,
    finished: bool,
    /// Bytes of earlier units of the current commit.
    commit_bytes: usize,
    /// Lines of the current commit assigned so far.
    commit_lines: usize,
    parser: UnitParser,
}

impl PatchStream {
    pub(super) fn new(limits: GitLimits) -> Self {
        Self {
            limits,
            buffer: Vec::new(),
            unit_start: 0,
            scan: 0,
            search: 0,
            finished: false,
            commit_bytes: 0,
            commit_lines: 0,
            parser: UnitParser::new(limits),
        }
    }

    /// Appends output. Call [`Self::next_file`] until it returns `None`
    /// before the next push, so each push can release parsed units.
    pub(super) fn push(&mut self, chunk: &[u8]) -> PatchResult<()> {
        if self.unit_start > 0 {
            self.buffer.drain(..self.unit_start);
            self.scan -= self.unit_start;
            self.search -= self.unit_start;
            self.unit_start = 0;
            // Release the space of an earlier large record.
            if self.buffer.capacity() > 8 * STDOUT_CHUNK_BYTES
                && self.buffer.len() < self.buffer.capacity() / 4
            {
                self.buffer
                    .shrink_to(self.buffer.len().max(2 * STDOUT_CHUNK_BYTES));
            }
        }
        self.buffer
            .try_reserve(chunk.len())
            .map_err(|error| patch_allocation("Git patch output", error))?;
        self.buffer.extend_from_slice(chunk);
        Ok(())
    }

    /// Marks the end of output, so the final unit can be parsed.
    pub(super) fn finish(&mut self) {
        self.finished = true;
    }

    /// Returns the next parsed file record whose unit is complete.
    pub(super) fn next_file(
        &mut self,
        cancellation: &dyn Cancellation,
    ) -> PatchResult<Option<ParsedFile>> {
        while let Some((start, end, boundary_follows)) = self.next_unit(cancellation)? {
            if let Some(file) =
                self.parser
                    .parse_unit(&self.buffer[start..end], boundary_follows, cancellation)?
            {
                return Ok(Some(file));
            }
        }
        Ok(None)
    }

    /// Assigns lines to the current unit and returns its range once the next
    /// unit starts or output ends. The flag tells whether a unit start follows.
    fn next_unit(
        &mut self,
        cancellation: &dyn Cancellation,
    ) -> PatchResult<Option<(usize, usize, bool)>> {
        let mut lines = 0_usize;
        loop {
            if lines.is_multiple_of(1024) {
                poll_patch_cancellation(cancellation)?;
            }
            lines += 1;
            if self.scan == self.buffer.len() {
                if self.finished && self.scan > self.unit_start {
                    let unit = (self.unit_start, self.scan, false);
                    self.unit_start = self.scan;
                    return Ok(Some(unit));
                }
                return Ok(None);
            }
            let newline = self.buffer[self.search..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map(|at| self.search + at + 1);
            if newline.is_none() {
                self.search = self.buffer.len();
            }
            let complete = newline.is_some() || self.finished;
            let end = newline.unwrap_or(self.buffer.len());
            let start = classify_line(&self.buffer[self.scan..end], complete);
            match start {
                LineStart::Undecided => return Ok(None),
                LineStart::Commit | LineStart::Diff if self.scan > self.unit_start => {
                    let unit = (self.unit_start, self.scan, true);
                    if start == LineStart::Commit {
                        self.commit_bytes = 0;
                        self.commit_lines = 0;
                    } else {
                        self.commit_bytes = self
                            .commit_bytes
                            .checked_add(self.scan - self.unit_start)
                            .ok_or_else(|| {
                                PatchError::Limit("Git patch size overflowed usize".to_owned())
                            })?;
                    }
                    self.unit_start = self.scan;
                    return Ok(Some(unit));
                }
                _ => {}
            }
            let commit_bytes = self
                .commit_bytes
                .checked_add(end - self.unit_start)
                .ok_or_else(|| PatchError::Limit("Git patch size overflowed usize".to_owned()))?;
            if commit_bytes > self.limits.patch_bytes() {
                return Err(PatchError::Limit(format!(
                    "Git patch output for one commit exceeds the configured {}-byte ceiling",
                    self.limits.patch_bytes()
                )));
            }
            if !complete {
                return Ok(None);
            }
            self.commit_lines += 1;
            if self.commit_lines > self.limits.patch_lines() {
                return Err(PatchError::Limit(format!(
                    "Git patch output for one commit exceeds the configured {}-line ceiling",
                    self.limits.patch_lines()
                )));
            }
            self.scan = end;
            self.search = end;
        }
    }
}

/// Parser state carried from one unit to the next.
struct UnitParser {
    limits: GitLimits,
    commit: Vec<u8>,
    metadata: Option<CommitMetadata>,
    /// Files and hunks of the current commit.
    files: usize,
    hunks: usize,
    /// Number of `commit ` lines seen, which identifies a file's commit.
    #[cfg(any(test, feature = "fuzzing"))]
    commits: usize,
}

impl UnitParser {
    fn new(limits: GitLimits) -> Self {
        Self {
            limits,
            commit: Vec::new(),
            metadata: Some(zero_commit_metadata()),
            files: 0,
            hunks: 0,
            #[cfg(any(test, feature = "fuzzing"))]
            commits: 0,
        }
    }

    /// Parses one unit. A unit holds at most one file record, because every
    /// record line starts a new unit.
    fn parse_unit(
        &mut self,
        unit: &[u8],
        boundary_follows: bool,
        cancellation: &dyn Cancellation,
    ) -> PatchResult<Option<ParsedFile>> {
        let lines = split_inclusive_lines(unit, self.limits.patch_lines(), cancellation)?;
        let Some(first) = lines.first() else {
            return Ok(None);
        };
        if let Some(value) = first.strip_prefix(b"commit ") {
            self.files = 0;
            self.hunks = 0;
            #[cfg(any(test, feature = "fuzzing"))]
            {
                self.commits += 1;
            }
            self.commit = copy_limited(
                trim_line(value),
                self.limits.metadata_bytes(),
                "Git commit SHA",
            )?;
            let (metadata, next) = parse_commit_header(
                &lines,
                0,
                &self.commit,
                self.limits.metadata_bytes(),
                cancellation,
            )?;
            self.metadata = Some(metadata);
            check_blank_lines(&lines[next..], cancellation)?;
            return Ok(None);
        }
        if first.starts_with(b"diff --git ") {
            return self.parse_record(&lines, boundary_follows, cancellation);
        }
        check_blank_lines(&lines, cancellation)?;
        Ok(None)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the record state machine is intentionally linear"
    )]
    fn parse_record(
        &mut self,
        lines: &[&[u8]],
        boundary_follows: bool,
        cancellation: &dyn Cancellation,
    ) -> PatchResult<Option<ParsedFile>> {
        let limits = self.limits;
        let mut file = ParsedFile {
            path: parse_diff_fallback(lines[0], limits.path_bytes(), cancellation)?
                .unwrap_or_default(),
            commit: copy_limited(&self.commit, limits.metadata_bytes(), "Git file commit SHA")?,
            metadata: self
                .metadata
                .as_ref()
                .map(|metadata| fallible_clone_metadata(metadata, limits.metadata_bytes()))
                .transpose()?,
            deleted: false,
            binary: false,
            hunks: Vec::new(),
            #[cfg(any(test, feature = "fuzzing"))]
            commit_index: self.commits,
        };
        let mut saw_old_path = false;
        let mut saw_new_path = false;
        let mut saw_old_mode = false;
        let mut saw_new_mode = false;
        let mut saw_rename_from = false;
        let mut saw_rename_to = false;
        let mut saw_copy_from = false;
        let mut saw_copy_to = false;
        let mut saw_file_lifecycle_mode = false;
        let mut binary_payload = false;
        let mut index = 1;
        while index < lines.len() {
            poll_patch_cancellation(cancellation)?;
            let line = lines[index];
            if binary_payload {
                index += 1;
                continue;
            }
            if line.starts_with(b"deleted file mode ") {
                file.deleted = true;
                saw_file_lifecycle_mode = true;
            } else if let Some(value) = line.strip_prefix(b"+++ ") {
                if !saw_old_path {
                    return Err(PatchError::Invalid(
                        "Git new-path header precedes its old-path header".to_owned(),
                    ));
                }
                saw_new_path = true;
                let value = trim_line(value);
                if value == b"/dev/null" {
                    file.deleted = true;
                } else {
                    file.path = decode_patch_path(value, true, limits.path_bytes(), cancellation)?;
                }
            } else if line.starts_with(b"Binary files ") {
                file.binary = true;
            } else if line.starts_with(b"GIT binary patch") {
                file.binary = true;
                binary_payload = true;
            } else if line.starts_with(b"@@ -") {
                self.hunks = self.hunks.checked_add(1).ok_or_else(|| {
                    PatchError::Limit("Git hunk count overflowed usize".to_owned())
                })?;
                if self.hunks > limits.hunks() {
                    return Err(PatchError::Limit(format!(
                        "Git patch for one commit exceeds the configured {}-hunk ceiling",
                        limits.hunks()
                    )));
                }
                let (hunk, next) = parse_hunk(lines, index, boundary_follows, cancellation)?;
                file.hunks
                    .try_reserve(1)
                    .map_err(|error| patch_allocation("Git hunks", error))?;
                file.hunks.push(hunk);
                index = next;
                continue;
            } else if line.starts_with(b"--- ") {
                saw_old_path = true;
            } else if line.starts_with(b"old mode ") {
                saw_old_mode = true;
            } else if line.starts_with(b"new file mode ") {
                saw_new_mode = true;
                saw_file_lifecycle_mode = true;
            } else if line.starts_with(b"new mode ") {
                saw_new_mode = true;
            } else if line.starts_with(b"rename from ") {
                saw_rename_from = true;
            } else if let Some(value) = line.strip_prefix(b"rename to ") {
                if !saw_rename_from {
                    return Err(PatchError::Invalid(
                        "Git rename destination has no source".to_owned(),
                    ));
                }
                file.path =
                    decode_patch_path(trim_line(value), false, limits.path_bytes(), cancellation)?;
                saw_rename_to = true;
            } else if line.starts_with(b"copy from ") {
                saw_copy_from = true;
            } else if let Some(value) = line.strip_prefix(b"copy to ") {
                if !saw_copy_from {
                    return Err(PatchError::Invalid(
                        "Git copy destination has no source".to_owned(),
                    ));
                }
                file.path =
                    decode_patch_path(trim_line(value), false, limits.path_bytes(), cancellation)?;
                saw_copy_to = true;
            } else if line.starts_with(b"index ")
                || line.starts_with(b"similarity index ")
                || line.starts_with(b"dissimilarity index ")
                || trim_line(line).is_empty()
            {
                // Auxiliary headers and separators do not make a record valid.
            } else {
                return Err(PatchError::Invalid(
                    "Git diff record contains an unexpected line".to_owned(),
                ));
            }
            index += 1;
        }
        let valid_structure = file.binary
            || !file.hunks.is_empty()
            || (saw_old_path && saw_new_path)
            || (saw_old_mode && saw_new_mode)
            || saw_file_lifecycle_mode
            || (saw_rename_from && saw_rename_to)
            || (saw_copy_from && saw_copy_to);
        if !valid_structure {
            return Err(PatchError::Invalid(
                "Git diff record contains incomplete or unrecognized structure".to_owned(),
            ));
        }
        if file.path.is_empty() {
            return Ok(None);
        }
        if self.files >= limits.files() {
            return Err(PatchError::Limit(format!(
                "Git patch for one commit exceeds the configured {}-file ceiling",
                limits.files()
            )));
        }
        self.files += 1;
        Ok(Some(file))
    }
}

fn check_blank_lines(lines: &[&[u8]], cancellation: &dyn Cancellation) -> PatchResult<()> {
    for line in lines {
        poll_patch_cancellation(cancellation)?;
        if !trim_line(line).is_empty() {
            return Err(PatchError::Invalid(
                "Git patch contains an unrecognized nonempty preamble".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Parses output delivered in chunks of the given sizes. Returns the files
/// that a streaming consumer would receive and the error that ended parsing.
#[cfg(any(test, feature = "fuzzing"))]
pub(super) fn parse_patch_chunks(
    input: &[u8],
    mut chunk_size: impl FnMut() -> usize,
    limits: GitLimits,
    cancellation: &dyn Cancellation,
) -> (Vec<ParsedFile>, Option<PatchError>) {
    fn drain(
        stream: &mut PatchStream,
        files: &mut Vec<ParsedFile>,
        cancellation: &dyn Cancellation,
    ) -> Option<PatchError> {
        loop {
            match stream.next_file(cancellation) {
                Ok(Some(file)) => files.push(file),
                Ok(None) => return None,
                Err(error) => return Some(error),
            }
        }
    }
    let mut stream = PatchStream::new(limits);
    let mut files = Vec::new();
    let mut rest = input;
    while !rest.is_empty() {
        let (chunk, tail) = rest.split_at(chunk_size().clamp(1, rest.len()));
        rest = tail;
        if let Err(error) = stream.push(chunk) {
            return (files, Some(error));
        }
        if let Some(error) = drain(&mut stream, &mut files, cancellation) {
            return (files, Some(error));
        }
    }
    stream.finish();
    let error = drain(&mut stream, &mut files, cancellation);
    (files, error)
}

/// Parses complete output in one chunk.
#[cfg(test)]
pub(super) fn parse_patch(
    input: &[u8],
    limits: GitLimits,
    cancellation: &dyn Cancellation,
) -> PatchResult<Vec<ParsedFile>> {
    match parse_patch_chunks(input, || input.len(), limits, cancellation) {
        (files, None) => Ok(files),
        (_, Some(error)) => Err(error),
    }
}

/// Exercises the in-process Git patch parser for the standalone fuzz target.
///
/// This entry point is available only with the `fuzzing` feature and exposes
/// no parser implementation types. Production users should use [`GitSource`].
/// It also checks that one-byte and varied chunks give the same files and
/// error as the whole input.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_parse_patch(
    input: &[u8],
    limits: GitLimits,
    cancellation: &dyn Cancellation,
) -> Option<(usize, usize)> {
    let whole = parse_patch_chunks(input, || input.len(), limits, cancellation);
    let mut state = input.iter().fold(0x9e37_79b9_u32, |state, byte| {
        state.rotate_left(5) ^ u32::from(*byte)
    }) | 1;
    let varied = parse_patch_chunks(
        input,
        || {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            usize::try_from(state % 97).unwrap_or(0) + 1
        },
        limits,
        cancellation,
    );
    assert!(
        varied == whole,
        "varied Git patch chunks must parse like the whole output"
    );
    let single = parse_patch_chunks(input, || 1, limits, cancellation);
    assert!(
        single == whole,
        "one-byte Git patch chunks must parse like the whole output"
    );
    let (files, error) = whole;
    if error.is_some() {
        return None;
    }
    let mut hunks = 0_usize;
    let mut commit_files = 0_usize;
    let mut commit_hunks = 0_usize;
    let mut commit = None;
    for file in &files {
        assert!(
            file.path.len() <= limits.path_bytes(),
            "successful Git patch path exceeded its parser limit"
        );
        if commit != Some(file.commit_index) {
            commit = Some(file.commit_index);
            commit_files = 0;
            commit_hunks = 0;
        }
        commit_files += 1;
        commit_hunks = commit_hunks
            .checked_add(file.hunks.len())
            .expect("bounded Git patch hunk count must fit usize");
        assert!(
            commit_files <= limits.files(),
            "successful Git commit file count exceeded its parser limit"
        );
        assert!(
            commit_hunks <= limits.hunks(),
            "successful Git commit hunk count exceeded its parser limit"
        );
        hunks = hunks
            .checked_add(file.hunks.len())
            .expect("bounded Git patch hunk count must fit usize");
    }
    Some((files.len(), hunks))
}

fn parse_commit_header(
    lines: &[&[u8]],
    start: usize,
    sha: &[u8],
    metadata_limit: usize,
    cancellation: &dyn Cancellation,
) -> PatchResult<(CommitMetadata, usize)> {
    let mut author_name = Vec::new();
    let mut author_email = Vec::new();
    let mut date = copy_limited(b"0001-01-01T00:00:00Z", metadata_limit, "Git commit date")?;
    let mut index = start + 1;
    while index < lines.len()
        && !lines[index].starts_with(b"diff --git ")
        && !lines[index].starts_with(b"commit ")
    {
        poll_patch_cancellation(cancellation)?;
        let line = lines[index];
        if trim_line(line).is_empty() {
            index += 1;
            break;
        }
        if let Some(author) = line.strip_prefix(b"Author: ") {
            let author = trim_line(author);
            if let Some(open) = author.iter().rposition(|byte| *byte == b'<')
                && author.ends_with(b">")
            {
                author_name = copy_limited(
                    trim_unicode_space(&author[..open]),
                    metadata_limit,
                    "Git author name",
                )?;
                author_email = copy_limited(
                    &author[open + 1..author.len() - 1],
                    metadata_limit,
                    "Git author email",
                )?;
            }
        } else if let Some(value) = line
            .strip_prefix(b"Date:   ")
            .or_else(|| line.strip_prefix(b"AuthorDate: "))
            && let Some(parsed) = git_date_to_rfc3339(trim_line(value), metadata_limit)?
        {
            date = parsed;
        }
        index += 1;
    }
    while index < lines.len() && trim_line(lines[index]).is_empty() {
        poll_patch_cancellation(cancellation)?;
        index += 1;
    }
    let mut message_lines = Vec::new();
    while index < lines.len()
        && !lines[index].starts_with(b"diff --git ")
        && !lines[index].starts_with(b"commit ")
    {
        poll_patch_cancellation(cancellation)?;
        let line = trim_line(lines[index]);
        message_lines
            .try_reserve(1)
            .map_err(|error| patch_allocation("Git commit message lines", error))?;
        message_lines.push(line);
        index += 1;
    }
    while message_lines.last().is_some_and(|line| line.is_empty()) {
        message_lines.pop();
    }
    let message = join_message(&message_lines, metadata_limit, cancellation)?;
    let metadata_size = sha
        .len()
        .checked_add(author_name.len())
        .and_then(|size| size.checked_add(author_email.len()))
        .and_then(|size| size.checked_add(date.len()))
        .and_then(|size| size.checked_add(message.len()))
        .ok_or_else(|| PatchError::Limit("Git metadata size overflowed usize".to_owned()))?;
    if metadata_size > metadata_limit {
        return Err(PatchError::Limit(format!(
            "Git commit metadata exceeds the configured {metadata_limit}-byte ceiling"
        )));
    }
    let sha = copy_limited(sha, metadata_limit, "Git metadata SHA")?;
    Ok((
        CommitMetadata::builder()
            .sha(sha)
            .author_name(author_name)
            .author_email(author_email)
            .date(date)
            .message(message)
            .build(),
        index,
    ))
}

fn join_message(
    lines: &[&[u8]],
    metadata_limit: usize,
    cancellation: &dyn Cancellation,
) -> PatchResult<Vec<u8>> {
    let Some(first_nonempty) = lines
        .iter()
        .position(|line| !trim_unicode_space(line).is_empty())
    else {
        return Ok(Vec::new());
    };
    let indent_len = lines[first_nonempty]
        .len()
        .saturating_sub(trim_unicode_space_start(lines[first_nonempty]).len());
    let indent = &lines[first_nonempty][..indent_len];
    let mut title = Vec::new();
    let mut index = first_nonempty;
    while index < lines.len() {
        poll_patch_cancellation(cancellation)?;
        let line = trim_unicode_space(lines[index]);
        if line.is_empty() {
            break;
        }
        if !title.is_empty() {
            push_limited(&mut title, b" ", metadata_limit, "Git commit title")?;
        }
        push_limited(&mut title, line, metadata_limit, "Git commit title")?;
        index += 1;
    }
    while index < lines.len() && trim_unicode_space(lines[index]).is_empty() {
        poll_patch_cancellation(cancellation)?;
        index += 1;
    }
    let mut body = Vec::new();
    let mut pending_empty = false;
    while index < lines.len() {
        poll_patch_cancellation(cancellation)?;
        let mut line = trim_unicode_space_end(lines[index]);
        if !indent.is_empty() {
            line = line.strip_prefix(indent).unwrap_or(line);
        }
        if line.is_empty() {
            pending_empty = true;
        } else {
            if !body.is_empty() {
                push_limited(&mut body, b"\n", metadata_limit, "Git commit body")?;
                if pending_empty {
                    push_limited(&mut body, b"\n", metadata_limit, "Git commit body")?;
                }
            }
            push_limited(&mut body, line, metadata_limit, "Git commit body")?;
            pending_empty = false;
        }
        index += 1;
    }
    if !body.is_empty() {
        push_limited(&mut title, b"\n\n", metadata_limit, "Git commit message")?;
        push_limited(&mut title, &body, metadata_limit, "Git commit message")?;
    }
    Ok(title)
}

fn parse_old_hunk_position(value: &[u8]) -> PatchResult<i64> {
    std::str::from_utf8(value)
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or_else(|| PatchError::Invalid("invalid Git old range position".to_owned()))
}

/// Parses one hunk. `boundary_follows` tells whether a commit or file record
/// line follows these lines, which is an invalid hunk line, not truncation.
fn parse_hunk(
    lines: &[&[u8]],
    start: usize,
    boundary_follows: bool,
    cancellation: &dyn Cancellation,
) -> PatchResult<(ParsedHunk, usize)> {
    let header = trim_line(lines[start]);
    let plus = header
        .windows(2)
        .position(|window| window == b" +")
        .ok_or_else(|| {
            PatchError::Invalid("invalid Git hunk header: missing new range".to_owned())
        })?;
    let range = &header[plus + 2..];
    let end = range
        .windows(3)
        .position(|window| window == b" @@")
        .ok_or_else(|| {
            PatchError::Invalid("invalid Git hunk header: missing range terminator".to_owned())
        })?;
    let range = &range[..end];
    let comma = range.iter().position(|byte| *byte == b',');
    let new_position =
        parse_usize(comma.map_or(range, |at| &range[..at])).map_err(PatchError::Invalid)?;
    let mut new_remaining = match comma {
        Some(at) => parse_usize(&range[at + 1..]).map_err(PatchError::Invalid)?,
        None => 1,
    };
    let minus = header
        .strip_prefix(b"@@ -")
        .ok_or_else(|| PatchError::Invalid("invalid Git hunk header prefix".to_owned()))?;
    let old_end = minus
        .iter()
        .position(|byte| *byte == b' ')
        .ok_or_else(|| PatchError::Invalid("invalid Git old range".to_owned()))?;
    let old_range = &minus[..old_end];
    let old_comma = old_range.iter().position(|byte| *byte == b',');
    parse_old_hunk_position(old_comma.map_or(old_range, |at| &old_range[..at]))?;
    let mut old_remaining = match old_comma {
        Some(at) => parse_usize(&old_range[at + 1..]).map_err(PatchError::Invalid)?,
        None => 1,
    };
    let mut added = Vec::new();
    let mut previous_added = false;
    let mut index = start + 1;
    while old_remaining > 0 || new_remaining > 0 {
        poll_patch_cancellation(cancellation)?;
        let line = lines
            .get(index)
            .copied()
            .ok_or_else(|| missing_hunk_line(boundary_follows))?;
        match line.first().copied() {
            Some(b'+') => {
                new_remaining = new_remaining.checked_sub(1).ok_or_else(|| {
                    PatchError::Invalid("Git hunk has too many additions".to_owned())
                })?;
                added
                    .try_reserve(line.len().saturating_sub(1))
                    .map_err(|error| patch_allocation("Git hunk bytes", error))?;
                added.extend_from_slice(&line[1..]);
                previous_added = true;
            }
            Some(b'-') => {
                old_remaining = old_remaining.checked_sub(1).ok_or_else(|| {
                    PatchError::Invalid("Git hunk has too many deletions".to_owned())
                })?;
                previous_added = false;
            }
            Some(b' ' | b'\n') => {
                old_remaining = old_remaining.checked_sub(1).ok_or_else(|| {
                    PatchError::Invalid("Git hunk has too much context".to_owned())
                })?;
                new_remaining = new_remaining.checked_sub(1).ok_or_else(|| {
                    PatchError::Invalid("Git hunk has too much context".to_owned())
                })?;
                previous_added = false;
            }
            Some(b'\\') if line.starts_with(b"\\ ") => {
                if previous_added && added.last() == Some(&b'\n') {
                    added.pop();
                }
            }
            _ => {
                return Err(PatchError::Invalid(
                    "invalid Git hunk line operation".to_owned(),
                ));
            }
        }
        index += 1;
    }
    if lines
        .get(index)
        .is_some_and(|line| line.starts_with(b"\\ "))
    {
        if previous_added && added.last() == Some(&b'\n') {
            added.pop();
        }
        index += 1;
    }
    Ok((
        ParsedHunk {
            new_position,
            added,
        },
        index,
    ))
}

/// A hunk that ends at a commit or record line has an invalid line there;
/// a hunk that ends with the output is truncated.
fn missing_hunk_line(boundary_follows: bool) -> PatchError {
    PatchError::Invalid(if boundary_follows {
        "invalid Git hunk line operation".to_owned()
    } else {
        "truncated Git hunk".to_owned()
    })
}

fn parse_diff_fallback(
    line: &[u8],
    path_limit: usize,
    cancellation: &dyn Cancellation,
) -> PatchResult<Option<Vec<u8>>> {
    let Some(value) = line.strip_prefix(b"diff --git ") else {
        return Ok(None);
    };
    let value = trim_line(value);
    let split = if value.starts_with(b"\"") {
        quoted_path_end(value, cancellation)?
    } else if let Some(quote) = value.iter().position(|byte| *byte == b'"') {
        quote.saturating_sub(1)
    } else {
        // Unquoted paths may contain spaces, including " b/". A default
        // name exists only when both complete names agree, so its separator
        // must be the midpoint. Rename/copy headers supply differing names.
        value.len() / 2
    };
    let (old, rest) = value.split_at(split);
    let Some(new) = rest.strip_prefix(b" ") else {
        return Ok(None);
    };
    let old = decode_patch_path(old, true, path_limit, cancellation)?;
    let new = decode_patch_path(new.trim_ascii_start(), true, path_limit, cancellation)?;
    Ok((old == new).then_some(new))
}

fn quoted_path_end(value: &[u8], cancellation: &dyn Cancellation) -> PatchResult<usize> {
    let mut escaped = false;
    for (index, byte) in value.iter().enumerate().skip(1) {
        poll_patch_cancellation(cancellation)?;
        if escaped {
            escaped = false;
        } else if *byte == b'\\' {
            escaped = true;
        } else if *byte == b'"' {
            return Ok(index + 1);
        }
    }
    Err(PatchError::Invalid(
        "unterminated quoted Git path".to_owned(),
    ))
}

pub(super) fn decode_patch_path(
    value: &[u8],
    tree_prefix: bool,
    path_limit: usize,
    cancellation: &dyn Cancellation,
) -> PatchResult<Vec<u8>> {
    poll_patch_cancellation(cancellation)?;
    let encoded_limit = if tree_prefix {
        path_limit
            .checked_add(2)
            .ok_or_else(|| PatchError::Limit("Git path ceiling overflowed usize".to_owned()))?
    } else {
        path_limit
    };
    let mut decoded = if value.starts_with(b"\"") {
        decode_c_quoted(value, encoded_limit, cancellation)?
    } else {
        copy_limited(value, encoded_limit, "Git path")?
    };
    if tree_prefix && (decoded.starts_with(b"a/") || decoded.starts_with(b"b/")) {
        decoded.drain(..2);
    }
    if tree_prefix {
        let mut previous_slash = false;
        decoded.retain(|byte| {
            let keep = *byte != b'/' || !previous_slash;
            previous_slash = *byte == b'/';
            keep
        });
    }
    if decoded.len() > path_limit {
        return Err(PatchError::Limit(format!(
            "Git path exceeds the configured {path_limit}-byte ceiling"
        )));
    }
    Ok(decoded)
}

fn decode_c_quoted(
    value: &[u8],
    path_limit: usize,
    cancellation: &dyn Cancellation,
) -> PatchResult<Vec<u8>> {
    if value.len() < 2 || value.last() != Some(&b'\"') {
        return Err(PatchError::Invalid(
            "unterminated quoted Git path".to_owned(),
        ));
    }
    let mut output = Vec::new();
    let mut index = 1;
    while index + 1 < value.len() {
        poll_patch_cancellation(cancellation)?;
        if output.len() >= path_limit {
            return Err(PatchError::Limit(format!(
                "Git path exceeds the configured {path_limit}-byte ceiling"
            )));
        }
        output
            .try_reserve(1)
            .map_err(|error| patch_allocation("decoded Git path", error))?;
        if value[index] != b'\\' {
            output.push(value[index]);
            index += 1;
            continue;
        }
        index += 1;
        let escaped = *value
            .get(index)
            .ok_or_else(|| PatchError::Invalid("truncated quoted Git path escape".to_owned()))?;
        match escaped {
            b'a' => output.push(0x07),
            b'b' => output.push(0x08),
            b't' => output.push(b'\t'),
            b'n' => output.push(b'\n'),
            b'v' => output.push(0x0b),
            b'f' => output.push(0x0c),
            b'r' => output.push(b'\r'),
            b'\\' | b'\"' => output.push(escaped),
            b'0'..=b'7' => {
                let mut octal = usize::from(escaped - b'0');
                let mut count = 1;
                while count < 3
                    && value
                        .get(index + 1)
                        .is_some_and(|byte| matches!(byte, b'0'..=b'7'))
                {
                    index += 1;
                    octal = octal * 8 + usize::from(value[index] - b'0');
                    count += 1;
                }
                output.push(u8::try_from(octal).map_err(|_| {
                    PatchError::Invalid("Git path octal escape overflow".to_owned())
                })?);
            }
            _ => {
                return Err(PatchError::Invalid(
                    "unsupported quoted Git path escape".to_owned(),
                ));
            }
        }
        index += 1;
    }
    Ok(output)
}

fn parse_usize(value: &[u8]) -> Result<usize, String> {
    std::str::from_utf8(value)
        .map_err(|_| "non-UTF-8 Git hunk range".to_owned())?
        .parse::<usize>()
        .map_err(|_| "invalid Git hunk range".to_owned())
}

pub(super) fn patch_error_to_source(
    error: PatchError,
    repository: &std::path::Path,
) -> SourceError {
    match error {
        PatchError::Cancelled => SourceError::Cancelled,
        PatchError::Limit(message) => {
            SourceError::terminal(SourceStage::Limit, Some(repository.into()), message)
        }
        PatchError::Invalid(message) => {
            SourceError::terminal(SourceStage::GitParse, Some(repository.into()), message)
        }
    }
}
